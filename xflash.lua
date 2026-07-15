--[[
    MediaTek DA "XFlash" (V5) protocol dissector for Wireshark

    This is a *stateful, length-delimited* dissector, modelled on the reference
    implementations (bkerler/mtkclient and penumbra). It does NOT scan for the
    frame magic. Scanning is unreliable because the host->device pipe interleaves
    magic-framed control frames with megabytes of RAW image data, and the 4-byte
    magic (EF EE EE FE) occurs by coincidence thousands of times inside that data.

    Wire format (little-endian), every logical message:
        [ magic : u32 = 0xFEEEEEEF ][ type : u32 ][ length : u32 ][ payload : length ]
        type 1 = DT_PROTOCOL_FLOW (commands, status, params, data)
        type 2 = DT_MESSAGE       (DA log text)

    How frames are told apart (there is nothing in a frame that says
    "I am a command" vs "a status" vs "a parameter" -- it is purely positional):
      * direction comes from the USB endpoint (IN = device->host, OUT = host->device)
      * host 4-byte flow frame whose value is a known command  -> COMMAND
        (DEVICE_CTRL is a two-step: the next host frame is the real sub-command)
      * host 4-byte flow frame value 0 / 0xFEEEEEEF             -> host ACK
      * other host frame                                        -> PARAMETER / bulk data
      * device 2/4-byte flow frame 0 / 0xFEEEEEEF / SYNC        -> STATUS OK
      * device 4-byte flow frame with 0xC0000000 bits           -> STATUS (error code)
      * other device frame                                      -> DATA response

    Parsing follows the length field frame-to-frame; large payloads (DA blob,
    image chunks) are consumed by byte-count and never scanned.
]]--

-- guard against being loaded twice (e.g. both xflash.lua and mtk_xflash.lua present)
if _G.__mtk_xflash_loaded then return end
_G.__mtk_xflash_loaded = true

local xf = Proto("xflash", "MTK DA XFlash")

-- ------------------------------------------------------------------ constants
local MAGIC       = 0xFEEEEEEF
local MAGIC_STR   = "\239\238\238\254"   -- EF EE EE FE
local SYNC        = 0x434E5953           -- "SYNC"
local DT_FLOW     = 1
local DT_MESSAGE  = 2
local DEVICE_CTRL = 0x010009
-- payloads longer than this are treated as opaque bulk data (never buffered/scanned)
local BIG_THRESHOLD = 0x2000

local CMDS = {
    [SYNC]="SYNC_SIGNAL",
    [0x010000]="UNKNOWN", [0x010001]="DOWNLOAD", [0x010002]="UPLOAD", [0x010003]="FORMAT",
    [0x010004]="WRITE_DATA", [0x010005]="READ_DATA", [0x010006]="FORMAT_PARTITION",
    [0x010007]="SHUTDOWN", [0x010008]="BOOT_TO", [0x010009]="DEVICE_CTRL",
    [0x01000A]="INIT_EXT_RAM", [0x01000B]="SWITCH_USB_SPEED", [0x01000C]="READ_OTP_ZONE",
    [0x01000D]="WRITE_OTP_ZONE", [0x01000E]="WRITE_EFUSE", [0x01000F]="READ_EFUSE",
    [0x010010]="NAND_BMT_REMARK", [0x010011]="SRAM_WRITE_TEST",
    [0x010100]="SETUP_ENVIRONMENT", [0x010101]="SETUP_HW_INIT_PARAMS",
    [0x020001]="SET_BMT_PERCENTAGE", [0x020002]="SET_BATTERY_OPT", [0x020003]="SET_CHECKSUM_LEVEL",
    [0x020004]="SET_RESET_KEY", [0x020005]="SET_HOST_INFO", [0x020006]="SET_META_BOOT_MODE",
    [0x020007]="SET_EMMC_HWRESET_PIN", [0x020008]="SET_GENERATE_GPX", [0x020009]="SET_REGISTER_VALUE",
    [0x02000A]="SET_EXTERNAL_SIG", [0x02000B]="SET_REMOTE_SEC_POLICY", [0x02000C]="SET_ALL_IN_ONE_SIG",
    [0x02000D]="SET_RSC_INFO", [0x02000E]="SET_REBOOT_MODE", [0x02000F]="SET_CERT_FILE",
    [0x020010]="SET_UPDATE_FW", [0x020011]="SET_UFS_CONFIG", [0x020012]="SET_DYNAMIC_PART_MAP",
    [0x040001]="GET_EMMC_INFO", [0x040002]="GET_NAND_INFO", [0x040003]="GET_NOR_INFO",
    [0x040004]="GET_UFS_INFO", [0x040005]="GET_DA_VERSION", [0x040006]="GET_EXPIRE_DATA",
    [0x040007]="GET_PACKET_LENGTH", [0x040008]="GET_RANDOM_ID", [0x040009]="GET_PARTITION_TBL_CATA",
    [0x04000A]="GET_CONNECTION_AGENT", [0x04000B]="GET_USB_SPEED", [0x04000C]="GET_RAM_INFO",
    [0x04000D]="GET_CHIP_ID", [0x04000E]="GET_OTP_LOCK_STATUS", [0x04000F]="GET_BATTERY_VOLTAGE",
    [0x040010]="GET_RPMB_STATUS", [0x040011]="GET_EXPIRE_DATE", [0x040012]="GET_DRAM_TYPE",
    [0x040013]="GET_DEV_FW_INFO", [0x040014]="GET_HRID", [0x040015]="GET_ERROR_DETAIL",
    [0x040016]="SLA_ENABLED_STATUS",
    [0x080001]="START_DL_INFO", [0x080002]="END_DL_INFO", [0x080003]="ACT_LOCK_OTP_ZONE",
    [0x080004]="DISABLE_EMMC_HWRESET_PIN", [0x080005]="CC_OPTIONAL_DOWNLOAD_ACT",
    [0x080007]="DA_STOR_LIFE_CYCLE_CHECK", [0x080008]="DISABLE_SPARSE_ERASE",
    [0x0E0000]="UNKNOWN_CTRL_CODE", [0x0E0001]="CTRL_STORAGE_TEST", [0x0E0002]="CTRL_RAM_TEST",
    [0x0E0003]="DEVICE_CTRL_READ_REGISTER",
    [0x0F0000]="EXT_ACK", [0x0F0001]="EXT_SETUP_DA_CTX", [0x0F0002]="EXT_READ_MEM",
    [0x0F0003]="EXT_WRITE_MEM", [0x0F0004]="EXT_READ_REGISTER", [0x0F0005]="EXT_WRITE_REGISTER",
    [0x0F0006]="EXT_KEY_DERIVE", [0x0F0007]="EXT_SEJ", [0x0F0008]="EXT_RPMB_INIT",
    [0x0F0009]="EXT_RPMB_READ", [0x0F000A]="EXT_RPMB_WRITE",
}

-- Curated status/error codes (structure: 0xC0000000 | domain<<16 | code).
-- Anything not listed is decoded generically from that structure.
local ERR = {
    [0xC0010001]="PROTOCOL_ERR", [0xC0010002]="ABORT", [0xC0010003]="UNSUPPORTED_COMMAND",
    [0xC0010004]="UNSUPPORTED_CTRL_CODE", [0xC0010005]="PROTOCOL_ERROR",
    [0xC0010006]="PROTOCOL_BUFFER_OVERFLOW", [0xC0010007]="INSUFFICIENT_BUFFER",
    [0xC0010008]="USB_SCAN_ERROR", [0xC001000C]="NOT_IMPLEMENTED", [0xC001000D]="FILE_NOT_FOUND",
    [0xC0020002]="CUST_NAME_NOT_FOUND", [0xC0020003]="DEVICE_NOT_SUPPORTED",
    [0xC0020004]="DL_FORBIDDEN", [0xC0020005]="IMG_TOO_LARGE", [0xC0020006]="PL_VERIFY_FAILED",
    [0xC0020007]="IMAGE_VERIFY_FAILED", [0xC002002D]="ANTI_ROLLBACK_VIOLATION",
    [0xC002002E]="SECCFG_NOT_FOUND", [0xC0020052]="INVALID_PARTITION_NAME",
    [0xC0020053]="DA_VERSION_ANTI_ROLLBACK",
    [0xC0030002]="DA_FILE_INVALID", [0xC0030006]="STORAGE_MISMATCH", [0xC0030008]="INVALID_GPT",
    [0xC003000E]="PARTITION_TBL_MISSING",
    [0xC0040001]="UNSUPPORTED_OPERATION", [0xC0040003]="CHECKSUM_ERROR",
    [0xC0040006]="PARTITION_NOT_FOUND", [0xC0040009]="UNKNOWN_STORAGE_TYPE",
    [0xC004000B]="EXCEED_AVAILABLE_RANGE", [0xC0040050]="EMI_SETTING_VERSION_ERROR",
}
local ERR_DOMAIN = { [1]="Protocol", [2]="Security", [3]="Library", [4]="Device" }

local STORAGE = {
    [0x1]="EMMC", [0x2]="SDMMC", [0x10]="NAND", [0x11]="NAND_SLC", [0x12]="NAND_MLC",
    [0x13]="NAND_TLC", [0x20]="NOR", [0x30]="UFS",
}
local EMMC_PART = {
    [0]="USER?", [1]="BOOT1", [2]="BOOT2", [3]="RPMB", [4]="GP1", [5]="GP2",
    [6]="GP3", [7]="GP4", [8]="USER", [9]="END",
}

-- ------------------------------------------------------------------ fields
local vs_type = { [DT_FLOW]="Protocol Flow", [DT_MESSAGE]="DA Message (log)" }
local f = xf.fields
f.magic  = ProtoField.uint32("xflash.magic",  "Magic",      base.HEX)
f.type   = ProtoField.uint32("xflash.type",   "Type",       base.DEC, vs_type)
f.length = ProtoField.uint32("xflash.length", "Length",     base.DEC)
f.dir    = ProtoField.string("xflash.dir",    "Direction")
f.kind   = ProtoField.string("xflash.kind",   "Frame kind")
f.cmd    = ProtoField.uint32("xflash.cmd",    "Command",    base.HEX, CMDS)
f.status = ProtoField.uint32("xflash.status", "Status",     base.HEX)
f.cksum  = ProtoField.uint16("xflash.checksum","Chunk checksum", base.HEX)
f.param  = ProtoField.bytes ("xflash.param",  "Parameter")
f.data   = ProtoField.bytes ("xflash.data",   "Data")
f.text   = ProtoField.string("xflash.text",   "Text")
f.part   = ProtoField.string("xflash.partition","Partition")
f.progress = ProtoField.string("xflash.progress","Flash progress")
f.info   = ProtoField.string("xflash.info",   "Summary")

local pe_resync = ProtoExpert.new("xflash.resync", "XFlash lost frame sync, resynchronised",
                                  expert.group.MALFORMED, expert.severity.WARN)
xf.experts = { pe_resync }

-- ------------------------------------------------------------------ USB metadata
local fe_ep   = Field.new("usb.endpoint_address")
local fe_bus  = Field.new("usb.bus_id")
local fe_dev  = Field.new("usb.device_address")
local fe_dlen = Field.new("usb.data_len")   -- TRUE transfer size (survives snaplen truncation)

-- ------------------------------------------------------------------ helpers
local function u32(s, o) local a,b,c,d = s:byte(o+1,o+4); if not d then return nil end
    return a + b*256 + c*65536 + d*16777216 end
local function u16(s, o) local a,b = s:byte(o+1,o+2); if not b then return nil end return a + b*256 end
local function u64(s, o) local lo=u32(s,o); local hi=u32(s,o+4); if not hi then return nil end
    return lo + hi*4294967296 end

local function hexprefix(s, n)
    n = math.min(#s, n or 16)
    local t = {}
    for i = 1, n do t[i] = string.format("%02X", s:byte(i)) end
    local r = table.concat(t)
    if #s > n then r = r .. ".." end
    return r
end

local function human(n)
    if n >= 0x100000 then return string.format("%.2f MB", n/0x100000) end
    if n >= 0x400   then return string.format("%.1f KB", n/0x400) end
    return string.format("%d B", n)
end

-- build a synthetic Tvb from raw bytes so per-frame fields decode correctly even
-- when a frame spans several USB packets (reassembly).
local function raw_to_tvb(raw, name)
    local t = {}
    for i = 1, #raw do t[i] = string.format("%02x", raw:byte(i)) end
    return ByteArray.new(table.concat(t)):tvb(name or "XFlash frame")
end

-- status-code decode -> (name, is_ok)
local function decode_status(v)
    if v == 0 or v == MAGIC or v == SYNC then return "OK", true end
    local named = ERR[v]
    if named then return named, false end
    if v >= 0xC0000000 then
        local dom = math.floor(v / 0x10000) % 0x100
        local code = v % 0x10000
        return string.format("ERR %s(%d) code=0x%X", ERR_DOMAIN[dom] or "?", dom, code), false
    end
    return nil, nil
end

-- decode a few well-known parameter/response structs -> short human string
local function decode_struct(ctx, dir_in, len, p)
    if not dir_in then          -- host -> device parameters
        if len == 20 then       -- EnvParams (SETUP_ENVIRONMENT)
            return string.format("Env{log_lvl=%d ch=%d os=%d ufs_prov=%d}",
                u32(p,0), u32(p,4), u32(p,8), u32(p,12))
        elseif len >= 48 and len <= 56 then   -- FlashOpParams (WRITE_DATA/READ_DATA/FORMAT)
            -- pack("<IIQQ", storage, parttype, addr, size) + NandExtension tail.
            -- 48 bytes on older DAs, 52/56 on newer ones; leading 24 bytes match.
            local st, pt = u32(p,0), u32(p,4)
            return string.format("FlashOp{storage=%s part=%s addr=0x%X size=0x%X}",
                STORAGE[st] or st, EMMC_PART[pt] or pt, u64(p,8), u64(p,16))
        elseif len == 16 then   -- BootTo addr+len (u64,u64)
            return string.format("addr=0x%X len=0x%X", u64(p,0), u64(p,8))
        end
    else
        -- device -> host responses, decoded by the DEVICE_CTRL query that asked.
        -- Field layouts mirror mtkclient's xflash_lib get_* parsers.
        if ctx == "GET_CHIP_ID" and len >= 10 then
            return string.format("hw_code=0x%04X hw_sub=0x%04X hw_ver=0x%04X sw_ver=0x%04X evo=0x%04X",
                u16(p,0), u16(p,2), u16(p,4), u16(p,6), u16(p,8))
        elseif ctx == "GET_EMMC_INFO" and len >= 72 then
            return string.format("eMMC block=0x%X boot1=0x%X boot2=0x%X rpmb=0x%X user=0x%X",
                u32(p,4), u64(p,8), u64(p,16), u64(p,24), u64(p,64))
        elseif ctx == "GET_RAM_INFO" and len == 48 then
            return string.format("SRAM base=0x%X size=0x%X | DRAM base=0x%X size=0x%X",
                u64(p,8), u64(p,16), u64(p,32), u64(p,40))
        elseif ctx == "GET_RAM_INFO" and len == 24 then
            return string.format("SRAM base=0x%X size=0x%X | DRAM base=0x%X size=0x%X",
                u32(p,4), u32(p,8), u32(p,16), u32(p,20))
        elseif ctx == "GET_NAND_INFO" and len >= 32 then
            return string.format("NAND page=0x%X block=0x%X spare=0x%X total=0x%X avail=0x%X",
                u32(p,4), u32(p,8), u32(p,12), u64(p,16), u64(p,24))
        elseif ctx == "GET_NOR_INFO" and len >= 16 then
            return string.format("NOR page=0x%X size=0x%X", u32(p,4), u64(p,8))
        elseif ctx == "GET_UFS_INFO" and len >= 32 then
            return string.format("UFS block=0x%X lu0=0x%X lu1=0x%X lu2=0x%X",
                u32(p,4), u64(p,24), u64(p,16), u64(p,8))
        elseif len == 8 then    -- PacketLenParams (GET_PACKET_LENGTH)
            return string.format("pkt_len{write=0x%X read=0x%X}", u32(p,0), u32(p,4))
        end
    end
    -- printable ascii: partition names ("PGPT"/"super"), "preloader", "high-speed"
    if len == 4 then
        if not p:find("[^%g ]") then return "'" .. p .. "'" end   -- all four printable
    elseif len >= 5 and len <= 72 then
        local s = p
        local nul = s:find("%z"); if nul then s = s:sub(1, nul - 1) end
        if #s >= 2 and s:match("^[%g ]+$") then return "'" .. s .. "'" end
    end
    return nil
end

-- ------------------------------------------------------------------ state
-- sessions[key] holds per-endpoint reassembly buffers + shared transaction state.
local sessions, results
local flash_totals = {}   -- partition name -> declared total size (for the summary window)
function xf.init()
    sessions = {}
    results  = {}   -- results[pkt_number] = { list of frame-event records }
    flash_totals = {}
end

local function get_session(key)
    local s = sessions[key]
    if not s then
        s = { eps = {}, last_cmd = nil, expect_subcmd = false, seq = 0 }
        sessions[key] = s
    end
    return s
end

local function get_ep(sess, epaddr)
    local e = sess.eps[epaddr]
    if not e then
        e = { buf = "", need = 0, locked = false, big = nil,   -- IN byte-stream state
              hdr = nil, pbuf = "", ptrunc = false }            -- OUT URB-frame state
        sess.eps[epaddr] = e
    end
    return e
end

-- Is `buf` (0-based offset `pos0`) the start of a plausible real frame?
local function frame_ok(buf, pos0)
    local m = u32(buf, pos0)
    if m ~= MAGIC then return false end
    local t = u32(buf, pos0 + 4)
    if t ~= DT_FLOW and t ~= DT_MESSAGE then return false end
    local ln = u32(buf, pos0 + 8)
    if not ln or ln > 0x8000000 then return false end
    -- if the following frame is already buffered, it must also be a magic
    local nxt = pos0 + 12 + ln
    if nxt + 4 <= #buf then
        if u32(buf, nxt) ~= MAGIC then return false end
    end
    return true
end

-- ------------------------------------------------------------- classification
-- Turn one complete flow/message frame into a display event record and advance
-- the transaction state machine. `raw` = full frame bytes (header+payload).
local function classify(sess, dir_in, dtype, len, payload, raw, pkt)
    local ev = { dir_in = dir_in, dtype = dtype, len = len, raw = raw }

    if dtype == DT_MESSAGE then
        ev.kind = "log"
        ev.text = (payload:gsub("[%z%c]", " ")):gsub("%s+$", "")
        ev.label = "LOG: " .. ev.text:sub(1, 60)
        return ev
    end

    local v = (len >= 4) and u32(payload, 0) or (len == 2 and u16(payload, 0)) or nil

    if dir_in then
        -- device -> host
        local sname, ok
        if (len == 2 or len == 4) and v ~= nil then sname, ok = decode_status(v) end
        if sname then
            ev.kind   = ok and "status_ok" or "status_err"
            ev.status = v
            ev.label  = ok and "STATUS OK" or ("STATUS " .. sname)
            return ev
        end
        -- data response
        ev.kind = "data_resp"; ev.value = v
        local ctx = sess.last_cmd
        local decoded = decode_struct(ctx, true, len, payload)
        ev.text = decoded
        ev.label = string.format("DATA[%d]%s%s", len,
            ctx and (" <"..ctx..">") or "", decoded and (" "..decoded) or (" "..hexprefix(payload)))
        return ev
    end

    -- host -> device
    if sess.expect_subcmd and len == 4 and CMDS[v] then
        sess.expect_subcmd = false
        sess.last_cmd = CMDS[v]
        if v == 0x080002 then sess.flash = nil end        -- END_DL_INFO closes a flash
        ev.kind = "subcmd"; ev.cmd = v; ev.label = "  ↳ " .. CMDS[v]
        return ev
    end
    if len == 4 and CMDS[v] then
        sess.seq = sess.seq + 1
        sess.last_cmd = CMDS[v]
        sess.expect_subcmd = (v == DEVICE_CTRL)
        if v == 0x010001 then                              -- DOWNLOAD (by partition name)
            sess.flash = { mode = "download", written = 0, chunks = 0 }
        elseif v == 0x010004 then                          -- WRITE_DATA (by address)
            sess.flash = { mode = "write", written = 0, chunks = 0 }
        end
        ev.kind = "cmd"; ev.cmd = v; ev.seq = sess.seq
        ev.label = string.format("CMD %s", CMDS[v])
        return ev
    end
    -- inside the image write loop, each chunk is [flag 0][checksum][2 MB data]
    if sess.flash and sess.flash.ready and len == 4 then
        if sess.flash.expect == "flag" and v == 0 then
            sess.flash.expect = "cksum"
            ev.kind = "chunk_flag"; ev.label = "chunk flag"; return ev
        elseif sess.flash.expect == "cksum" then
            sess.flash.expect = "data"
            ev.kind = "chunk_cksum"; ev.cksum = v % 0x10000
            ev.label = string.format("chunk checksum 0x%04X", v % 0x10000); return ev
        end
    end
    if len == 4 and (v == 0 or v == MAGIC) then
        ev.kind = "ack"; ev.status = v; ev.label = "ACK"
        return ev
    end
    -- parameter
    ev.kind = "param"; ev.value = v
    local decoded = decode_struct(sess.last_cmd, false, len, payload)
    ev.text = decoded
    -- learn what/how-much is being flashed (name + size, or FlashOpParams)
    if sess.flash and not sess.flash.ready then
        if sess.flash.mode == "download" then
            if not sess.flash.part and decoded and decoded:sub(1, 1) == "'" then
                sess.flash.part = decoded:gsub("'", ""); ev.part = sess.flash.part
            elseif sess.flash.part and len == 8 then
                sess.flash.total = u64(payload, 0)
                sess.flash.ready = true; sess.flash.expect = "flag"
                flash_totals[sess.flash.part] = sess.flash.total
            end
        elseif sess.flash.mode == "write" and len == 48 then
            sess.flash.part  = string.format("addr 0x%X", u64(payload, 8))
            sess.flash.total = u64(payload, 16)
            sess.flash.ready = true; sess.flash.expect = "flag"; ev.part = sess.flash.part
            flash_totals[sess.flash.part] = sess.flash.total
        end
    end
    if len == 4 then
        ev.label = decoded and ("param " .. decoded) or string.format("param 0x%08X", v or 0)
    else
        ev.label = string.format("param[%d]%s", len, decoded and (" "..decoded) or (" "..hexprefix(payload)))
    end
    return ev
end

-- ------------------------------------------------------------- reassembly
-- The two directions frame differently on the wire, so they reassemble
-- differently:
--   * host->device (OUT) is URB-delimited: a 12-byte magic header URB, then a
--     payload URB. Large payloads (image chunks, DA blob) are TRUNCATED by the
--     capture snaplen, so we advance by usb.data_len (the true size), not by the
--     bytes actually present.
--   * device->host (IN) is a byte stream (the DA writes status frames a byte at
--     a time), never truncated, so we length-follow the reassembled bytes.

-- Emit the frame event for a completed OUT frame held in ep.hdr / ep.pbuf.
local function finish_out_frame(sess, ep, pkt)
    local h = ep.hdr
    local ev
    if h.dtype == DT_FLOW and h.len > BIG_THRESHOLD then
        local fl = sess.flash
        if fl and fl.ready and fl.expect == "data" then      -- an image chunk
            fl.written = fl.written + h.len
            fl.chunks  = fl.chunks + 1
            fl.expect  = "flag"
            local prog = (fl.total and fl.total > 0)
                and string.format("%s / %s (%d%%)", human(fl.written), human(fl.total),
                                   math.floor(fl.written / fl.total * 100))
                or  human(fl.written)
            ev = { dir_in = false, kind = "image", len = h.len, part = fl.part, progress = prog,
                   big = { len = h.len, trunc = ep.ptrunc },
                   label = string.format("%s  %s · chunk %d", fl.part or "?", prog, fl.chunks) }
        else                                                  -- DA blob, etc.
            ev = { dir_in = false, kind = "data_blk", len = h.len,
                   big = { len = h.len, trunc = ep.ptrunc },
                   label = string.format("TX DATA %s%s", human(h.len),
                                         ep.ptrunc and " (truncated in capture)" or "") }
        end
    else
        ev = classify(sess, false, h.dtype, h.len, ep.pbuf, h.raw .. ep.pbuf, pkt)
    end
    ep.hdr = nil; ep.pbuf = ""; ep.ptrunc = false
    return ev
end

-- OUT: one URB = captured bytes C plus a truncation gap so its true size is T.
local function feed_out(sess, ep, C, T, pkt)
    local events = {}
    local clen = #C

    -- collecting the payload of an in-progress frame?
    if ep.need > 0 then
        local take = (T < ep.need) and T or ep.need
        ep.need = ep.need - take
        if clen > 0 and #ep.pbuf < 0x400 then
            ep.pbuf = ep.pbuf .. C:sub(1, math.min(clen, 0x400 - #ep.pbuf))
        end
        if T > clen then ep.ptrunc = true end
        if ep.need == 0 then
            events[#events+1] = finish_out_frame(sess, ep, pkt)
        else
            events[#events+1] = { dir_in = false, kind = "data_cont",
                                  label = string.format("… TX payload +%s", human(T)) }
        end
        return events
    end

    -- expecting a frame header (12-byte magic URB, possibly with inline payload)
    if clen >= 12 and u32(C, 0) == MAGIC then
        local dtype = u32(C, 4)
        if dtype == DT_FLOW or dtype == DT_MESSAGE then
            local flen = u32(C, 8)
            ep.hdr = { dtype = dtype, len = flen, raw = C:sub(1, 12) }
            ep.pbuf = ""; ep.ptrunc = false
            if flen == 0 then
                events[#events+1] = finish_out_frame(sess, ep, pkt)
                return events
            end
            local logical_here = T - 12          -- payload bytes (logical) in this URB
            local captured_here = clen - 12       -- payload bytes actually captured here
            if logical_here <= 0 then
                ep.need = flen                    -- payload arrives in following URB(s)
            else
                if captured_here > 0 then
                    ep.pbuf = C:sub(13, 12 + math.min(captured_here, 0x400))
                end
                if T > clen then ep.ptrunc = true end
                if logical_here >= flen then
                    events[#events+1] = finish_out_frame(sess, ep, pkt)
                else
                    ep.need = flen - logical_here
                end
            end
            return events
        end
    end

    -- not an xflash header: BROM handshake / DA upload / raw bytes -> ignore
    return events
end

-- IN: byte-stream length-following over the reassembled device->host bytes.
local function feed_in(sess, ep, data, pkt)
    local events = {}

    if ep.need > 0 then            -- consuming a large response payload
        local n = math.min(ep.need, #data)
        ep.need = ep.need - n
        ep.big.got = ep.big.got + n
        events[#events+1] = { dir_in = true, kind = "data_cont", big = ep.big,
                              label = string.format("… RX data +%s (%s/%s)",
                                  human(n), human(ep.big.got), human(ep.big.len)) }
        if ep.need > 0 then return events end
        data = data:sub(n + 1)
        ep.big = nil
    end

    ep.buf = ep.buf .. data

    while true do
        if not ep.locked then
            local pos, scan = nil, ep.buf:find(MAGIC_STR, 1, true)
            while scan do
                if frame_ok(ep.buf, scan - 1) then pos = scan; break end
                scan = ep.buf:find(MAGIC_STR, scan + 1, true)
            end
            if not pos then
                if #ep.buf > 0x40000 then ep.buf = ep.buf:sub(-0x1000) end
                break
            end
            if pos > 1 then ep.buf = ep.buf:sub(pos) end
            ep.locked = true
        end

        if #ep.buf < 12 then break end
        if u32(ep.buf, 0) ~= MAGIC then
            local nx = ep.buf:find(MAGIC_STR, 2, true)
            while nx and not frame_ok(ep.buf, nx - 1) do
                nx = ep.buf:find(MAGIC_STR, nx + 1, true)
            end
            if not nx then ep.buf = ep.buf:sub(-3); break end
            ep.buf = ep.buf:sub(nx)
            events[#events+1] = { dir_in = true, kind = "resync", label = "«resync»" }
        else
            local dtype = u32(ep.buf, 4)
            local flen  = u32(ep.buf, 8)
            if flen > BIG_THRESHOLD then
                local avail = #ep.buf - 12
                local big = { len = flen, got = math.min(avail, flen) }
                if avail >= flen then
                    ep.buf = ep.buf:sub(12 + flen + 1)
                    events[#events+1] = { dir_in = true, kind = "data_blk", len = flen, big = big,
                        label = string.format("RX DATA %s", human(flen)) }
                else
                    ep.need = flen - avail; ep.big = big; ep.buf = ""
                    events[#events+1] = { dir_in = true, kind = "data_blk", len = flen, big = big,
                        label = string.format("RX DATA %s (start)", human(flen)) }
                    break
                end
            else
                if #ep.buf < 12 + flen then break end
                local raw     = ep.buf:sub(1, 12 + flen)
                local payload = ep.buf:sub(13, 12 + flen)
                ep.buf = ep.buf:sub(12 + flen + 1)
                events[#events+1] = classify(sess, true, dtype, flen, payload, raw, pkt)
            end
        end
    end

    return events
end

-- ------------------------------------------------------------- rendering
local function render_event(tree, pinfo, ev)
    local st = tree:add(xf, "XFlash: " .. (ev.label or ev.kind))
    st:add(f.dir,  ev.dir_in and "device->host" or "host->device")
    st:add(f.kind, ev.kind)
    if ev.part     then st:add(f.part, ev.part) end
    if ev.progress then st:add(f.progress, ev.progress) end

    if ev.raw then
        local ftvb = raw_to_tvb(ev.raw)
        st:add_le(f.magic,  ftvb(0, 4))
        st:add_le(f.type,   ftvb(4, 4))
        st:add_le(f.length, ftvb(8, 4))
        if ev.cmd    then st:add_le(f.cmd,    ftvb(12, 4)) end
        if ev.status then st:add_le(f.status, ftvb(12, 4))
            local nm = select(1, decode_status(ev.status)); if nm then st:append_text(" ("..nm..")") end
        end
        if ev.cksum   then st:add_le(f.cksum, ftvb(12, 2)) end
        if ev.kind == "param"     and ev.len > 0 then st:add(f.param, ftvb(12, ev.len)) end
        if ev.kind == "data_resp" and ev.len > 0 then st:add(f.data,  ftvb(12, ev.len)) end
        if ev.text then st:add(f.text, ev.text) end
    else
        if ev.big then
            st:add(f.length, ev.big.len):append_text(" ("..ev.kind..")")
        end
    end
    if ev.kind == "resync" then st:add_proto_expert_info(pe_resync) end
    return st
end

-- ------------------------------------------------------------- dissector
function xf.dissector(tvb, pinfo, root)
    local len = tvb:len()
    if len == 0 then return end

    -- USB metadata (endpoint carries direction in bit 0x80)
    local ep_fi = fe_ep()
    if not ep_fi then return end        -- not a USB bulk packet we understand
    local epaddr = ep_fi.value
    local dir_in = (epaddr >= 0x80)
    local bus    = fe_bus() and fe_bus().value or 0
    local dev    = fe_dev() and fe_dev().value or 0
    local key    = bus * 0x1000000 + dev * 0x100 + (epaddr % 0x80)  -- pipe (both dirs share)

    local sess = get_session(key)
    local ep   = get_ep(sess, epaddr)

    -- first pass: run reassembly + state machine, cache the result per packet
    if not pinfo.visited then
        local events
        if dir_in then
            events = feed_in(sess, ep, tvb:raw(), pinfo.number)
        else
            local truelen = fe_dlen() and fe_dlen().value or tvb:len()
            events = feed_out(sess, ep, tvb:raw(), truelen, pinfo.number)
        end
        if #events > 0 then results[pinfo.number] = events end
    end

    local events = results[pinfo.number]
    if not events then return end   -- fragment-only packet: leave it as plain USB, keeps the xflash view clean

    pinfo.cols.protocol = "XFLASH"
    local tree = root:add(xf, tvb(), "MediaTek DA XFlash")

    local summary = {}
    for _, ev in ipairs(events) do
        render_event(tree, pinfo, ev)
        summary[#summary+1] = ev.label or ev.kind
        -- flow view: one expert "chat" line per frame, chronological
        tree:add_expert_info(expert.group.SEQUENCE, expert.severity.CHAT,
            (ev.dir_in and "D<- " or "H-> ") .. (ev.label or ev.kind))
    end
    -- direction prefix of the first event drives the column tag
    local first_in = events[1].dir_in
    pinfo.cols.info = (first_in and "[DEV] " or "[HOST] ") .. table.concat(summary, " | ")
end

-- ------------------------------------------------------------- registration
local function register()
    -- MTK DA bulk interface is vendor-specific / unknown class.
    local bulk = DissectorTable.get("usb.bulk")
    if bulk then
        bulk:add(0xFF,   xf)   -- vendor specific
        bulk:add(0xFFFF, xf)   -- unknown class (common for MTK DA captures)
    end
    local prod = DissectorTable.get("usb.product")
    if prod then
        prod:add(0x0E8D2000, xf)  -- MTK BROM
        prod:add(0x0E8D2001, xf)  -- MTK Preloader / DA
        prod:add(0x0E8D0003, xf)
    end
end
register()

-- ------------------------------------------------------------- session summary
-- Device identity + what the session did, reachable in the GUI at
-- Tools ▸ MTK XFlash ▸ Flash summary. Accumulates from dissected frames, so it
-- works even on a partial capture that never reaches END_DL_INFO.
-- Field extractors MUST be created at load time (not inside the menu callback).
local CHIPS = {   -- hw_code -> SoC name (mtkclient brom_config; first part number)
    [0x279]="MT6797", [0x321]="MT6735", [0x326]="MT6755", [0x335]="MT6737M",
    [0x337]="MT6753", [0x507]="MT6759", [0x551]="MT6757", [0x562]="MT6799",
    [0x601]="MT6750", [0x688]="MT6758", [0x690]="MT6763", [0x699]="MT6739",
    [0x707]="MT6768/69", [0x717]="MT6761/62", [0x725]="MT6779", [0x766]="MT6765",
    [0x788]="MT6771", [0x813]="MT6785", [0x816]="MT6885", [0x886]="MT6873",
    [0x907]="MT6983", [0x930]="MT8195", [0x950]="MT6891/93", [0x959]="MT6877",
    [0x989]="MT6833", [0x992]="MT6880", [0x996]="MT6853", [0x1066]="MT6781",
    [0x1129]="MT6855", [0x1172]="MT6895", [0x1203]="MT6897", [0x1208]="MT6789",
    [0x1209]="MT6835V", [0x1229]="MT6886", [0x1236]="MT6989W", [0x1296]="MT6985",
    [0x1357]="MT6991", [0x1375]="MT6878", [0x1471]="MT6993", [0x6580]="MT6580",
    [0x6595]="MT6595", [0x6752]="MT6752", [0x6795]="MT6795", [0x8127]="MT8127",
    [0x8163]="MT8163", [0x8167]="MT8167", [0x8176]="MT8176",
}

local sf_part = Field.new("xflash.partition")
local sf_len  = Field.new("xflash.length")
local sf_kind = Field.new("xflash.kind")
local sf_cmd  = Field.new("xflash.cmd")
local sf_text = Field.new("xflash.text")

local function hsize(n)   -- byte count -> GiB/MiB/KiB (storage & RAM are large)
    if n >= 0x40000000 then return string.format("%.2f GiB", n / 0x40000000) end
    if n >= 0x100000   then return string.format("%.1f MiB", n / 0x100000)   end
    if n >= 0x400      then return string.format("%.1f KiB", n / 0x400)      end
    return tostring(n) .. " B"
end
-- true if `s` reports a non-zero size for `pat` (every storage type is queried;
-- only the one actually present has non-zero fields)
local function present(s, pat)
    local v = tonumber((s:match(pat)) or "0", 16)
    return v and v > 0
end

local function show_flash_summary()
    local acc, errors = {}, 0
    local cmdhist, ncmd = {}, 0
    local dev = {}
    local tap = Listener.new(nil, "xflash")
    local win = TextWindow.new("MTK XFlash — session summary")

    function tap.reset() acc, errors, cmdhist, ncmd, dev = {}, 0, {}, 0, {} end
    function tap.packet()
        local ki = sf_kind(); if not ki then return end
        local kind = tostring(ki.value)

        local c = sf_cmd()
        if c then cmdhist[c.value] = (cmdhist[c.value] or 0) + 1; ncmd = ncmd + 1 end

        local t = sf_text()
        if t then
            local s = tostring(t.value)
            if     s:find("^hw_code=")                              then dev.chip = s
            elseif s:find("^eMMC ") and present(s, "user=0x(%x+)")  then dev.emmc = s
            elseif s:find("^UFS ")  and present(s, "lu0=0x(%x+)")   then dev.ufs  = s
            elseif s:find("^NAND ") and present(s, "total=0x(%x+)") then dev.nand = s
            elseif s:find("^SRAM ")                                 then dev.ram  = s
            end
        end

        if kind == "image" then
            local p = sf_part() and tostring(sf_part().value) or "?"
            local a = acc[p] or { w = 0, c = 0 }
            a.w = a.w + (sf_len() and sf_len().value or 0)
            a.c = a.c + 1
            acc[p] = a
        elseif kind == "status_err" then
            errors = errors + 1
        end
    end
    function tap.draw()
        local out = {}

        out[#out + 1] = "=== Device ===\n"
        if dev.chip then
            local hw = tonumber((dev.chip:match("hw_code=0x(%x+)")) or "", 16)
            local sw = dev.chip:match("sw_ver=0x%x+")
            out[#out + 1] = string.format("  SoC:     %s (hw_code 0x%X%s)\n",
                (hw and CHIPS[hw]) or "unknown", hw or 0, sw and (", " .. sw) or "")
        end
        if dev.emmc then
            local u = tonumber((dev.emmc:match("user=0x(%x+)")) or "", 16)
            out[#out + 1] = string.format("  Storage: eMMC%s\n", u and (" — user " .. hsize(u)) or "")
            out[#out + 1] = "           " .. dev.emmc .. "\n"
        elseif dev.ufs then
            local l = tonumber((dev.ufs:match("lu0=0x(%x+)")) or "", 16)
            out[#out + 1] = string.format("  Storage: UFS%s\n", l and (" — LU0 " .. hsize(l)) or "")
            out[#out + 1] = "           " .. dev.ufs .. "\n"
        elseif dev.nand then
            out[#out + 1] = "  Storage: NAND — " .. dev.nand .. "\n"
        end
        if dev.ram then
            local d = tonumber((dev.ram:match("DRAM base=0x%x+ size=0x(%x+)")) or "", 16)
            out[#out + 1] = string.format("  DRAM:    %s\n", d and hsize(d) or dev.ram)
        end
        if not dev.chip and not dev.emmc and not dev.ufs then
            out[#out + 1] = "  (no device info — device→host direction not recorded in this capture)\n"
        end

        out[#out + 1] = string.format("\n=== What it did (%d commands) ===\n", ncmd)
        local rows = {}
        for cv, n in pairs(cmdhist) do rows[#rows + 1] = { cv = cv, n = n } end
        table.sort(rows, function(a, b) if a.n ~= b.n then return a.n > b.n end return a.cv < b.cv end)
        for _, e in ipairs(rows) do
            out[#out + 1] = string.format("  %-24s %d\n", CMDS[e.cv] or string.format("0x%X", e.cv), e.n)
        end

        local wn = {}
        for p in pairs(acc) do wn[#wn + 1] = p end
        if #wn > 0 then
            out[#out + 1] = "\n=== Partition writes ===\n"
            table.sort(wn)
            for _, p in ipairs(wn) do
                local a, total = acc[p], flash_totals[p]
                local pct = (total and total > 0)
                    and string.format("  —  %d%% of %s", math.floor(a.w / total * 100), human(total)) or ""
                out[#out + 1] = string.format("  %-16s %10s in %d chunks%s\n", p, human(a.w), a.c, pct)
            end
        end

        if errors > 0 then out[#out + 1] = string.format("\n! %d error status(es) seen\n", errors) end
        if ncmd == 0 then out[1] = "No XFlash (V5) traffic seen in this capture.\n" end

        win:set(table.concat(out))
        tap:remove()
    end
    win:set_atclose(function() tap:remove() end)
    retap_packets()
end

if gui_enabled() then
    register_menu("MTK XFlash/Flash summary", show_flash_summary, MENU_TOOLS_UNSORTED)
end
