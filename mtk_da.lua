--[[
    MediaTek DA combined dissector (V5 XFlash + V6 XMLFlash) for Wireshark

    This is the "both" plugin. It contains BOTH protocol engines and picks the
    right one automatically, per USB pipe, so you don't have to swap files when a
    capture is V5 vs V6.

    How detection works: V5 and V6 share the identical 12-byte wire header
        [ magic : u32 = 0xFEEEEEEF ][ type : u32 ][ length : u32 ][ payload ]
    and only differ in the payload. V5 payloads are binary command opcodes /
    status words; V6 payloads are XML / ASCII text ("<?xml ...>", "OK", "ERR!").
    sniff_version() peeks the first flow frame of each pipe and latches it to
    "v5" or "v6"; every later packet on that pipe uses the latched engine. Two
    devices of different versions in one capture are handled independently.

    Fields are unchanged from the standalone plugins: V5 frames expose xflash.*
    and V6 frames expose xmlflash.*, so existing display filters, custom columns
    and the mtk_xflash / mtk_xmlflash color rules all keep working.

    Install ONE of the three plugins, not several. This file also pre-sets the
    standalone load guards, so if xflash.lua / xmlflash.lua happen to be present
    too, they no-op and this combined plugin wins (it loads first alphabetically).
]]--

if _G.__mtk_da_loaded then return end
_G.__mtk_da_loaded = true
-- shadow the standalone plugins so they skip their own Proto()/register if also installed
_G.__mtk_xflash_loaded   = true
_G.__mtk_xmlflash_loaded = true

-- ================================================================= shared
local MAGIC        = 0xFEEEEEEF
local MAGIC_STR    = "\239\238\238\254"    -- EF EE EE FE
local MAGIC_B      = MAGIC_STR             -- V6 code refers to the magic bytes by this name
local SYNC         = 0x434E5953            -- "SYNC"
local DT_FLOW      = 1
local DT_MESSAGE   = 2
local DT_MSG       = DT_MESSAGE            -- V6 code uses this name
local HDR_LEN      = 12
local DEVICE_CTRL  = 0x010009
local BIG_THRESHOLD= 0x2000                -- V5: payloads bigger than this are opaque bulk

-- entry/dispatch proto (registered on USB); v5/v6 protos are field-only
local pd = Proto("mtkda",    "MediaTek DA (auto V5/V6)")
local p5 = Proto("xflash",   "MTK DA XFlash")
local p6 = Proto("xmlflash", "MTK DA XMLFlash V6")

-- USB metadata (extractors must be created at load time)
local fe_ep   = Field.new("usb.endpoint_address")
local fe_bus  = Field.new("usb.bus_id")
local fe_dev  = Field.new("usb.device_address")
local fe_dlen = Field.new("usb.data_len")   -- TRUE transfer size (survives snaplen truncation)

-- ---------------------------------------------------------------- helpers
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

-- synthetic Tvb from raw bytes so per-frame fields decode across USB packet splits
local function raw_to_tvb(raw, name)
    local t = {}
    for i = 1, #raw do t[i] = string.format("%02x", raw:byte(i)) end
    return ByteArray.new(table.concat(t)):tvb(name or "MTK DA frame")
end

local function xml_get(s, tag)   -- V6
    return s:match("<" .. tag .. ">(.-)</" .. tag .. ">") or ""
end
local function strip_null(s)     -- V6
    return s:gsub("%z+$", "")
end

-- ================================================================= V5 tables
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

local function decode_struct(ctx, dir_in, len, p)
    if not dir_in then
        if len == 20 then
            return string.format("Env{log_lvl=%d ch=%d os=%d ufs_prov=%d}",
                u32(p,0), u32(p,4), u32(p,8), u32(p,12))
        elseif len >= 48 and len <= 56 then
            -- READ_DATA/WRITE_DATA params: pack("<IIQQ", storage, parttype, addr,
            -- size) + a NandExtension tail. 48 bytes on older DAs, 52/56 on newer
            -- ones — the leading 24 bytes (the part that says WHAT is read/written)
            -- are identical, so decode them regardless of the tail size.
            local st, pt = u32(p,0), u32(p,4)
            return string.format("FlashOp{storage=%s part=%s addr=0x%X size=0x%X}",
                STORAGE[st] or st, EMMC_PART[pt] or pt, u64(p,8), u64(p,16))
        elseif len == 16 then
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
        elseif len == 8 then
            return string.format("pkt_len{write=0x%X read=0x%X}", u32(p,0), u32(p,4))
        end
    end
    if len == 4 then
        if not p:find("[^%g ]") then return "'" .. p .. "'" end
    elseif len >= 5 and len <= 72 then
        local s = p
        local nul = s:find("%z"); if nul then s = s:sub(1, nul - 1) end
        if #s >= 2 and s:match("^[%g ]+$") then return "'" .. s .. "'" end
    end
    return nil
end

-- ================================================================= fields
local vs_type = { [DT_FLOW]="Protocol Flow", [DT_MESSAGE]="DA Message (log)" }
local f5 = p5.fields
f5.magic  = ProtoField.uint32("xflash.magic",  "Magic",      base.HEX)
f5.type   = ProtoField.uint32("xflash.type",   "Type",       base.DEC, vs_type)
f5.length = ProtoField.uint32("xflash.length", "Length",     base.DEC)
f5.dir    = ProtoField.string("xflash.dir",    "Direction")
f5.kind   = ProtoField.string("xflash.kind",   "Frame kind")
f5.cmd    = ProtoField.uint32("xflash.cmd",    "Command",    base.HEX, CMDS)
f5.status = ProtoField.uint32("xflash.status", "Status",     base.HEX)
f5.cksum  = ProtoField.uint16("xflash.checksum","Chunk checksum", base.HEX)
f5.param  = ProtoField.bytes ("xflash.param",  "Parameter")
f5.data   = ProtoField.bytes ("xflash.data",   "Data")
f5.text   = ProtoField.string("xflash.text",   "Text")
f5.part   = ProtoField.string("xflash.partition","Partition")
f5.progress = ProtoField.string("xflash.progress","Flash progress")
f5.info   = ProtoField.string("xflash.info",   "Summary")

local pe_resync = ProtoExpert.new("xflash.resync", "XFlash lost frame sync, resynchronised",
                                  expert.group.MALFORMED, expert.severity.WARN)
p5.experts = { pe_resync }

local f6 = {
    magic    = ProtoField.uint32("xmlflash.magic",       "Magic",        base.HEX),
    dtype    = ProtoField.uint32("xmlflash.type",        "Data Type",    base.DEC,
                                 {[1]="Flow",[2]="Message"}),
    length   = ProtoField.uint32("xmlflash.length",      "Payload Length", base.DEC),
    dir      = ProtoField.string("xmlflash.dir",         "Direction"),
    kind     = ProtoField.string("xmlflash.kind",        "Kind"),
    cmd      = ProtoField.string("xmlflash.cmd",         "Command"),
    text     = ProtoField.string("xmlflash.text",        "Text"),
    xml      = ProtoField.string("xmlflash.xml",         "XML"),
    part     = ProtoField.string("xmlflash.partition",   "Partition"),
    progress = ProtoField.string("xmlflash.progress",    "Progress"),
    info     = ProtoField.string("xmlflash.info",        "Info"),
    priority = ProtoField.uint32("xmlflash.priority",    "Log Priority", base.DEC),
    data     = ProtoField.bytes("xmlflash.data",         "Data"),
    datalen  = ProtoField.uint32("xmlflash.data_length", "Data Length",  base.DEC),
}
p6.fields = { f6.magic, f6.dtype, f6.length, f6.dir, f6.kind, f6.cmd, f6.text,
              f6.xml, f6.part, f6.progress, f6.info, f6.priority, f6.data, f6.datalen }

-- ================================================================= state
local sessions_v5, sessions_v6, results, flash_totals, ver_by_key, predetect
function pd.init()
    sessions_v5  = {}
    sessions_v6  = {}
    results      = {}   -- results[pkt] = { ver = "v5"|"v6", events = {...} }
    flash_totals = {}
    ver_by_key   = {}   -- key -> "v5"|"v6" once a pipe's version is detected
    predetect    = {}   -- key -> { frames = {...}, size } buffered until the version
                        -- is known (the shared 12-byte header is ambiguous, and a
                        -- frame's header/payload can split across URBs)
end

-- =============================================================== V5 engine
local function get_session_v5(key)
    local s = sessions_v5[key]
    if not s then
        s = { eps = {}, last_cmd = nil, expect_subcmd = false, seq = 0 }
        sessions_v5[key] = s
    end
    return s
end
local function get_ep(sess, epaddr)
    local e = sess.eps[epaddr]
    if not e then
        e = { buf = "", need = 0, locked = false, big = nil,
              hdr = nil, pbuf = "", ptrunc = false }
        sess.eps[epaddr] = e
    end
    return e
end

local function frame_ok(buf, pos0)
    local m = u32(buf, pos0)
    if m ~= MAGIC then return false end
    local t = u32(buf, pos0 + 4)
    if t ~= DT_FLOW and t ~= DT_MESSAGE then return false end
    local ln = u32(buf, pos0 + 8)
    if not ln or ln > 0x8000000 then return false end
    local nxt = pos0 + 12 + ln
    if nxt + 4 <= #buf then
        if u32(buf, nxt) ~= MAGIC then return false end
    end
    return true
end

local function classify_v5(sess, dir_in, dtype, len, payload, raw, pkt)
    local ev = { dir_in = dir_in, dtype = dtype, len = len, raw = raw }

    if dtype == DT_MESSAGE then
        ev.kind = "log"
        ev.text = (payload:gsub("[%z%c]", " ")):gsub("%s+$", "")
        ev.label = "LOG: " .. ev.text:sub(1, 60)
        return ev
    end

    local v = (len >= 4) and u32(payload, 0) or (len == 2 and u16(payload, 0)) or nil

    if dir_in then
        local sname, ok
        if (len == 2 or len == 4) and v ~= nil then sname, ok = decode_status(v) end
        if sname then
            ev.kind   = ok and "status_ok" or "status_err"
            ev.status = v
            ev.label  = ok and "STATUS OK" or ("STATUS " .. sname)
            return ev
        end
        ev.kind = "data_resp"; ev.value = v
        local ctx = sess.last_cmd
        local decoded = decode_struct(ctx, true, len, payload)
        ev.text = decoded
        ev.label = string.format("DATA[%d]%s%s", len,
            ctx and (" <"..ctx..">") or "", decoded and (" "..decoded) or (" "..hexprefix(payload)))
        return ev
    end

    if sess.expect_subcmd and len == 4 and CMDS[v] then
        sess.expect_subcmd = false
        sess.last_cmd = CMDS[v]
        if v == 0x080002 then sess.flash = nil end
        ev.kind = "subcmd"; ev.cmd = v; ev.label = "  \226\134\179 " .. CMDS[v]
        return ev
    end
    if len == 4 and CMDS[v] then
        sess.seq = sess.seq + 1
        sess.last_cmd = CMDS[v]
        sess.expect_subcmd = (v == DEVICE_CTRL)
        if v == 0x010001 then
            sess.flash = { mode = "download", written = 0, chunks = 0 }
        elseif v == 0x010004 then
            sess.flash = { mode = "write", written = 0, chunks = 0 }
        end
        ev.kind = "cmd"; ev.cmd = v; ev.seq = sess.seq
        ev.label = string.format("CMD %s", CMDS[v])
        return ev
    end
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
    ev.kind = "param"; ev.value = v
    local decoded = decode_struct(sess.last_cmd, false, len, payload)
    ev.text = decoded
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

local function finish_out_frame_v5(sess, ep, pkt)
    local h = ep.hdr
    local ev
    if h.dtype == DT_FLOW and h.len > BIG_THRESHOLD then
        local fl = sess.flash
        if fl and fl.ready and fl.expect == "data" then
            fl.written = fl.written + h.len
            fl.chunks  = fl.chunks + 1
            fl.expect  = "flag"
            local prog = (fl.total and fl.total > 0)
                and string.format("%s / %s (%d%%)", human(fl.written), human(fl.total),
                                   math.floor(fl.written / fl.total * 100))
                or  human(fl.written)
            ev = { dir_in = false, kind = "image", len = h.len, part = fl.part, progress = prog,
                   big = { len = h.len, trunc = ep.ptrunc },
                   label = string.format("%s  %s \194\183 chunk %d", fl.part or "?", prog, fl.chunks) }
        else
            ev = { dir_in = false, kind = "data_blk", len = h.len,
                   big = { len = h.len, trunc = ep.ptrunc },
                   label = string.format("TX DATA %s%s", human(h.len),
                                         ep.ptrunc and " (truncated in capture)" or "") }
        end
    else
        ev = classify_v5(sess, false, h.dtype, h.len, ep.pbuf, h.raw .. ep.pbuf, pkt)
    end
    ep.hdr = nil; ep.pbuf = ""; ep.ptrunc = false
    return ev
end

local function feed_out_v5(sess, ep, C, T, pkt)
    local events = {}
    local clen = #C

    if ep.need > 0 then
        local take = (T < ep.need) and T or ep.need
        ep.need = ep.need - take
        if clen > 0 and #ep.pbuf < 0x400 then
            ep.pbuf = ep.pbuf .. C:sub(1, math.min(clen, 0x400 - #ep.pbuf))
        end
        if T > clen then ep.ptrunc = true end
        if ep.need == 0 then
            events[#events+1] = finish_out_frame_v5(sess, ep, pkt)
        else
            events[#events+1] = { dir_in = false, kind = "data_cont",
                                  label = string.format("\226\128\166 TX payload +%s", human(T)) }
        end
        return events
    end

    if clen >= 12 and u32(C, 0) == MAGIC then
        local dtype = u32(C, 4)
        if dtype == DT_FLOW or dtype == DT_MESSAGE then
            local flen = u32(C, 8)
            ep.hdr = { dtype = dtype, len = flen, raw = C:sub(1, 12) }
            ep.pbuf = ""; ep.ptrunc = false
            if flen == 0 then
                events[#events+1] = finish_out_frame_v5(sess, ep, pkt)
                return events
            end
            local logical_here = T - 12
            local captured_here = clen - 12
            if logical_here <= 0 then
                ep.need = flen
            else
                if captured_here > 0 then
                    ep.pbuf = C:sub(13, 12 + math.min(captured_here, 0x400))
                end
                if T > clen then ep.ptrunc = true end
                if logical_here >= flen then
                    events[#events+1] = finish_out_frame_v5(sess, ep, pkt)
                else
                    ep.need = flen - logical_here
                end
            end
            return events
        end
    end
    return events
end

local function feed_in_v5(sess, ep, data, pkt)
    local events = {}

    if ep.need > 0 then
        local n = math.min(ep.need, #data)
        ep.need = ep.need - n
        ep.big.got = ep.big.got + n
        events[#events+1] = { dir_in = true, kind = "data_cont", big = ep.big,
                              label = string.format("\226\128\166 RX data +%s (%s/%s)",
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
            events[#events+1] = { dir_in = true, kind = "resync", label = "\194\171resync\194\187" }
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
                events[#events+1] = classify_v5(sess, true, dtype, flen, payload, raw, pkt)
            end
        end
    end

    return events
end

local function render_event_v5(tree, pinfo, ev)
    local st = tree:add(p5, "XFlash: " .. (ev.label or ev.kind))
    st:add(f5.dir,  ev.dir_in and "device->host" or "host->device")
    st:add(f5.kind, ev.kind)
    if ev.part     then st:add(f5.part, ev.part) end
    if ev.progress then st:add(f5.progress, ev.progress) end

    if ev.raw then
        local ftvb = raw_to_tvb(ev.raw)
        st:add_le(f5.magic,  ftvb(0, 4))
        st:add_le(f5.type,   ftvb(4, 4))
        st:add_le(f5.length, ftvb(8, 4))
        if ev.cmd    then st:add_le(f5.cmd,    ftvb(12, 4)) end
        if ev.status then st:add_le(f5.status, ftvb(12, 4))
            local nm = select(1, decode_status(ev.status)); if nm then st:append_text(" ("..nm..")") end
        end
        if ev.cksum   then st:add_le(f5.cksum, ftvb(12, 2)) end
        if ev.kind == "param"     and ev.len > 0 then st:add(f5.param, ftvb(12, ev.len)) end
        if ev.kind == "data_resp" and ev.len > 0 then st:add(f5.data,  ftvb(12, ev.len)) end
        if ev.text then st:add(f5.text, ev.text) end
    else
        if ev.big then
            st:add(f5.length, ev.big.len):append_text(" ("..ev.kind..")")
        end
    end
    if ev.kind == "resync" then st:add_proto_expert_info(pe_resync) end
    return st
end

-- =============================================================== V6 engine
local function get_session_v6(key)
    local s = sessions_v6[key]
    if not s then
        s = { buf_out = "", hdr_out = nil, out_skip = 0, buf_in = "",
              last_cmd = nil, partition = nil, upload = nil }
        sessions_v6[key] = s
    end
    return s
end

local function classify_v6(sess, payload, dir_in)
    local text = strip_null(payload)
    local ev   = { dir_in = dir_in }

    if text:sub(1, 1) == "<" then
        local cmd_raw = xml_get(text, "command")
        local cmd     = cmd_raw:gsub("^CMD:", "")
        ev.xml_text   = text

        if text:find("<da>") or text:find("<da ") then
            ev.kind = "cmd";  ev.cmd = cmd
            sess.last_cmd = cmd
            local part = xml_get(text, "partition")
            if part ~= "" then ev.partition = part; sess.partition = part end
            local lbl = { cmd }
            local function add(k, v) if v ~= "" then lbl[#lbl + 1] = k .. "=" .. v end end
            add("partition", part)
            add("function", xml_get(text, "function"))
            add("key",      xml_get(text, "key"))
            add("offset",   xml_get(text, "offset"))
            add("mode",     xml_get(text, "mode"))
            ev.label = table.concat(lbl, " ")

        elseif text:find("<host>") or text:find("<host ") then
            if cmd == "DOWNLOAD-FILE" then
                ev.kind  = "negotiate"
                local info_f = xml_get(text, "info")
                ev.label = "DOWNLOAD-FILE"
                if info_f ~= "" then ev.label = ev.label .. " info=" .. info_f end
                sess.upload = { total = 0, sent = 0, chunks = 0 }
            elseif cmd == "UPLOAD-FILE" then
                ev.kind  = "negotiate"
                local info_f = xml_get(text, "info")
                ev.label = "UPLOAD-FILE"
                if info_f ~= "" then ev.label = ev.label .. " info=" .. info_f end
                -- readback (device->host): same framing as a download, track it too
                sess.upload = { total = 0, sent = 0, chunks = 0 }
            elseif cmd == "FILE-SYS-OPERATION" then
                ev.kind  = "file_op"
                local k  = xml_get(text, "key")
                ev.label = "FILE-SYS-OPERATION"
                if k ~= "" then ev.label = ev.label .. " " .. k end
            elseif cmd == "PROGRESS-REPORT" then
                ev.kind  = "progress_report"
                ev.label = "PROGRESS: " .. xml_get(text, "message")
            elseif cmd == "END" then
                ev.kind = "end_cmd"
                local r  = xml_get(text, "result")
                local m  = xml_get(text, "message")
                ev.label = "END"
                if r ~= "" then ev.label = ev.label .. " result=" .. r end
                if m ~= "" then ev.label = ev.label .. " " .. m end
                ev.result = r
                sess.upload = nil
            elseif cmd == "START" then
                ev.kind  = "start"
                ev.label = "START"
                sess.last_cmd = nil
                sess.upload   = nil
            else
                ev.kind  = "negotiate"
                ev.label = cmd ~= "" and cmd or "host-xml"
            end

        elseif text:find("<da_hw_info") then
            ev.kind  = "hw_info"
            local st = xml_get(text, "storage")
            ev.label = "HW-INFO"
            if st ~= "" then ev.label = ev.label .. " storage=" .. st end
        elseif text:find("<partition_table") then
            ev.kind  = "part_table"
            ev.label = "PARTITION-TABLE"
        elseif text:find("<da_info") then
            ev.kind  = "da_info"
            local v = xml_get(text, "da_version")
            ev.label = "DA-INFO"
            if v ~= "" then ev.label = ev.label .. " v" .. v end
        elseif text:find("<sla") then
            ev.kind  = "sla_info"
            ev.label = "SLA-INFO"
        else
            ev.kind  = dir_in and "xml_resp" or "xml_data"
            ev.label = "XML (" .. #text .. " B)"
        end
        return ev
    end

    if text:match("^OK!EOT") then
        ev.kind = "eot"; ev.label = "EOT"
    elseif text:match("^OK@") then
        ev.kind = "ack_len"
        local val = text:match("@(.+)$")
        ev.label = "OK @ " .. (val or "?")
        if sess.upload and sess.upload.total == 0 and val then
            local n = tonumber(val, 16) or tonumber(val)
            if n and n > 0 then sess.upload.total = n end
        end
    elseif text:match("^OK") then
        ev.kind = "ack"; ev.label = "OK"
    elseif text:match("^ERR!") then
        ev.kind = "err"
        ev.label = text
    elseif sess.upload then
        ev.kind     = "data"
        ev.data_len = #payload
        if sess.partition then ev.partition = sess.partition end
        sess.upload.sent   = sess.upload.sent + #payload
        sess.upload.chunks = sess.upload.chunks + 1
        ev.chunk_num = sess.upload.chunks
        if sess.upload.total > 0 then
            ev.progress_text = string.format("%s / %s (%d%%)",
                human(sess.upload.sent), human(sess.upload.total),
                math.floor(sess.upload.sent / sess.upload.total * 100))
        end
        ev.label = "DATA " .. human(#payload)
    elseif #text > 0 and text:byte(1) >= 0x20 then
        ev.kind = dir_in and "text_resp" or "text_data"
        ev.label = text:sub(1, 80)
    else
        ev.kind     = "data"
        ev.data_len = #payload
        if sess.partition then ev.partition = sess.partition end
        ev.label = "DATA " .. human(#payload)
    end
    ev.text = text
    return ev
end

local function feed_out_v6(sess, raw, pkt, events, truelen)
    local real_len
    if truelen then
        real_len = truelen                       -- caller supplied it (replay path)
    else
        local df = fe_dlen()
        real_len = (df and df.value > 0) and df.value or #raw
    end

    if sess.out_skip > 0 then
        local skip = math.min(sess.out_skip, real_len)
        sess.out_skip = sess.out_skip - skip
        raw = raw:sub(skip + 1)
        real_len = real_len - skip
        if #raw == 0 then return end
    end

    if not sess.hdr_out then
        if #raw < HDR_LEN then return end
        local mg = u32(raw, 0)
        if mg ~= MAGIC then return end
        local dtype = u32(raw, 4)
        local dlen  = u32(raw, 8)

        if dtype == DT_MSG then
            local body = raw:sub(HDR_LEN + 1)
            local prio, msg = 0, ""
            if #body >= 4 then
                prio = u32(body, 0)
                msg  = strip_null(body:sub(5))
            else
                msg = strip_null(body)
            end
            events[#events + 1] = {
                dir_in = false, kind = "log",
                label = "[LOG] " .. msg, priority_val = prio, text = msg,
            }
            return
        end

        if dlen == 0 then return end

        local payload_here = raw:sub(HDR_LEN + 1)
        local captured     = #payload_here
        local payload_real = real_len - HDR_LEN
        if payload_real < 0 then payload_real = 0 end

        if payload_real >= dlen then
            local payload = captured >= dlen
                and payload_here:sub(1, dlen)
                or  payload_here
            events[#events + 1] = classify_v6(sess, payload, false)
        else
            sess.hdr_out = { dtype = dtype, length = dlen, got = payload_real }
            sess.buf_out = payload_here
        end
    else
        local needed = sess.hdr_out.length
        sess.hdr_out.got = sess.hdr_out.got + real_len
        sess.buf_out = sess.buf_out .. raw

        if sess.hdr_out.got >= needed then
            local payload = #sess.buf_out >= needed
                and sess.buf_out:sub(1, needed)
                or  sess.buf_out
            events[#events + 1] = classify_v6(sess, payload, false)
            sess.hdr_out = nil
            sess.buf_out = ""
        end
    end
end

local function feed_in_v6(sess, raw, pkt, events)
    sess.buf_in = sess.buf_in .. raw

    while true do
        local buf = sess.buf_in
        if #buf < HDR_LEN then return end

        local pos = buf:find(MAGIC_B, 1, true)
        if not pos then
            sess.buf_in = ""
            return
        end
        if pos > 1 then
            sess.buf_in = buf:sub(pos)
            buf = sess.buf_in
        end
        if #buf < HDR_LEN then return end

        local mg    = u32(buf, 0)
        local dtype = u32(buf, 4)
        local dlen  = u32(buf, 8)

        if (dtype ~= DT_FLOW and dtype ~= DT_MSG) or dlen > 0x400000 then
            sess.buf_in = buf:sub(5)
        else
            local frame_len = HDR_LEN + dlen
            if #buf < frame_len then return end

            local payload = buf:sub(HDR_LEN + 1, frame_len)
            sess.buf_in   = buf:sub(frame_len + 1)

            if dtype == DT_MSG then
                local prio, msg = 0, ""
                if #payload >= 4 then
                    prio = u32(payload, 0)
                    msg  = strip_null(payload:sub(5))
                else
                    msg = strip_null(payload)
                end
                events[#events + 1] = {
                    dir_in = true, kind = "log",
                    label = "[LOG] " .. msg, priority_val = prio, text = msg,
                }
            else
                events[#events + 1] = classify_v6(sess, payload, true)
            end
        end
    end
end

local function render_event_v6(tree, ev, buf)
    local sub = tree:add(p6, buf())
    sub:add(f6.dir,  buf(), ev.dir_in and "device" or "host")
    sub:add(f6.kind, buf(), ev.kind)

    if ev.cmd       then sub:add(f6.cmd,      buf(), ev.cmd) end
    if ev.partition then sub:add(f6.part,     buf(), ev.partition) end
    if ev.xml_text  then sub:add(f6.xml,      buf(), ev.xml_text:sub(1, 2000)) end
    if ev.text      then sub:add(f6.text,     buf(), ev.text:sub(1, 500)) end
    if ev.data_len  then sub:add(f6.datalen,  buf(), ev.data_len) end

    if ev.progress_text then sub:add(f6.progress, buf(), ev.progress_text) end
    if ev.priority_val  then sub:add(f6.priority, buf(), ev.priority_val) end

    local info = ev.label or ev.kind
    sub:add(f6.info, buf(), info)
    sub:set_text(string.format("XMLFlash %s: %s",
        ev.dir_in and "DEV" or "HOST", info))
    return sub
end

-- =============================================================== detection
-- Peek the first magic-framed FLOW frame of a pipe and decide V5 vs V6.
-- V6 flow payloads are XML/ASCII ("<?xml", "OK", "ERR!"); V5 are binary
-- opcodes/status words. Returns "v5", "v6", or nil (undetermined -> retry next
-- packet). DT_MESSAGE (log text) is skipped: it looks textual in both versions.
local function sniff_version(dir_in, raw)
    -- Bare XML payload URB: a V6 device sends START as [header URB][XML URB], so
    -- the XML URB begins exactly with the declaration. Gate on size — this must be
    -- a small control frame, never a big binary chunk (V5 image data, which is
    -- full of embedded files, can start with '<' at a URB boundary).
    if #raw <= 0x2000 and raw:sub(1, 5) == "<?xml" then return "v6" end

    -- Otherwise look for a magic-framed flow header. Search (don't just check
    -- offset 0): the buffered detection window prepends unrelated pre-protocol
    -- bytes, so the real header sits somewhere inside. Skip false magics whose
    -- following bytes aren't a plausible flow header.
    local search = 1
    while true do
        local p = raw:find(MAGIC_STR, search, true)
        if not p then return nil end
        local pos = p - 1
        search = p + 1
        if #raw >= pos + 13 and u32(raw, pos + 4) == DT_FLOW then
            local flen = u32(raw, pos + 8)
            if flen and flen > 0 then
                -- Classify by the payload head, but ONLY for small control frames.
                -- A large flow frame is a V5 image/bulk chunk whose binary payload
                -- may coincidentally begin with '<' or "OK".
                if flen <= 0x2000 then
                    local b1   = raw:byte(pos + 13)
                    local head = raw:sub(pos + 13, pos + 20)
                    if b1 == 0x3C then return "v6" end                   -- '<'
                    if head:match("^OK") or head:match("^ERR!") then return "v6" end
                end
                -- positive V5 signal: a known command or a decodable status word
                if flen == 4 or flen == 2 then
                    local v = (flen == 4) and u32(raw, pos + 12) or u16(raw, pos + 12)
                    if v and (CMDS[v] or (select(1, decode_status(v)) ~= nil)) then return "v5" end
                end
                -- a fully-formed flow frame that is neither recognizably V6 nor a
                -- known V5 command: binary param/bulk -> V5
                return "v5"
            end
        end
    end
end

-- =============================================================== dispatcher
function pd.dissector(tvb, pinfo, root)
    if tvb:len() == 0 then return end

    local ep_fi = fe_ep()
    if not ep_fi then return end
    local epaddr = ep_fi.value
    local dir_in = (epaddr >= 0x80)
    local bus    = fe_bus() and fe_bus().value or 0
    local dev    = fe_dev() and fe_dev().value or 0
    local key    = bus * 0x1000000 + dev * 0x100 + (epaddr % 0x80)

    if not pinfo.visited then
        local truelen = (not dir_in) and (fe_dlen() and fe_dlen().value or tvb:len()) or nil
        local ver = ver_by_key[key]

        if not ver then
            -- Version unknown yet. The 12-byte header is identical in V5/V6, and a
            -- single frame's header and payload can arrive in separate URBs, so no
            -- lone URB is reliably classifiable. Buffer the URBs, sniff the
            -- concatenated per-direction stream, and once the version is known
            -- replay the buffer through the chosen engine so the frame that first
            -- reveals the version still renders on its own packet.
            -- Keep only a small rolling window of the most recent URBs — enough to
            -- span a header URB plus its payload URB. The pre-protocol phase (BROM
            -- handshake, DA-binary upload) can be megabytes and is not magic-framed,
            -- so it must roll through without unbounded growth and WITHOUT ever
            -- giving up: the moment real magic-framed traffic appears, we latch.
            local pr = predetect[key]
            if not pr then pr = { frames = {}, bytes = 0 }; predetect[key] = pr end
            local raw = tvb:raw()
            pr.frames[#pr.frames + 1] =
                { dir_in = dir_in, raw = raw, ep = epaddr, T = truelen, pkt = pinfo.number }
            pr.bytes = pr.bytes + #raw
            -- bound by both bytes and frame count (a V5 DA streams IN status one
            -- byte per URB, so a byte cap alone could leave thousands of frames)
            while #pr.frames > 2 and (pr.bytes > 0x8000 or #pr.frames > 64) do
                pr.bytes = pr.bytes - #pr.frames[1].raw
                table.remove(pr.frames, 1)
            end

            local outcat, incat = "", ""
            for _, fr in ipairs(pr.frames) do
                if fr.dir_in then incat = incat .. fr.raw else outcat = outcat .. fr.raw end
            end
            ver = (outcat ~= "" and sniff_version(false, outcat))
               or (incat  ~= "" and sniff_version(true,  incat)) or nil

            if not ver then return end
            ver_by_key[key] = ver

            if ver == "v5" then
                local sess = get_session_v5(key)
                for _, fr in ipairs(pr.frames) do
                    local ep  = get_ep(sess, fr.ep)
                    local evs = fr.dir_in and feed_in_v5(sess, ep, fr.raw, fr.pkt)
                                          or  feed_out_v5(sess, ep, fr.raw, fr.T, fr.pkt)
                    if fr.pkt == pinfo.number and evs and #evs > 0 then
                        results[pinfo.number] = { ver = "v5", events = evs }
                    end
                end
            else
                local sess = get_session_v6(key)
                for _, fr in ipairs(pr.frames) do
                    local evs = {}
                    if fr.dir_in then feed_in_v6(sess, fr.raw, fr.pkt, evs)
                    else                feed_out_v6(sess, fr.raw, fr.pkt, evs, fr.T) end
                    if fr.pkt == pinfo.number and #evs > 0 then
                        results[pinfo.number] = { ver = "v6", events = evs }
                    end
                end
            end
            predetect[key] = nil

        elseif ver == "v5" then
            local sess = get_session_v5(key)
            local ep   = get_ep(sess, epaddr)
            local events
            if dir_in then events = feed_in_v5(sess, ep, tvb:raw(), pinfo.number)
            else            events = feed_out_v5(sess, ep, tvb:raw(), truelen, pinfo.number) end
            if events and #events > 0 then results[pinfo.number] = { ver = "v5", events = events } end

        elseif ver == "v6" then
            local sess   = get_session_v6(key)
            local events = {}
            if dir_in then feed_in_v6(sess, tvb:raw(), pinfo.number, events)
            else            feed_out_v6(sess, tvb:raw(), pinfo.number, events, truelen) end
            if #events > 0 then results[pinfo.number] = { ver = "v6", events = events } end
        end
    end

    local rec = results[pinfo.number]
    if not rec then return end

    if rec.ver == "v5" then
        pinfo.cols.protocol = "XFLASH"
        local tree = root:add(p5, tvb(), "MediaTek DA XFlash")
        local summary = {}
        for _, ev in ipairs(rec.events) do
            render_event_v5(tree, pinfo, ev)
            summary[#summary+1] = ev.label or ev.kind
            tree:add_expert_info(expert.group.SEQUENCE, expert.severity.CHAT,
                (ev.dir_in and "D<- " or "H-> ") .. (ev.label or ev.kind))
        end
        pinfo.cols.info = (rec.events[1].dir_in and "[DEV] " or "[HOST] ")
                        .. table.concat(summary, " | ")
    else
        pinfo.cols.protocol = "XMLFlash"
        for _, ev in ipairs(rec.events) do
            local sub = render_event_v6(root, ev, tvb)
            sub:add_expert_info(expert.group.SEQUENCE, expert.severity.CHAT,
                (ev.dir_in and "D<- " or "H-> ") .. (ev.label or ev.kind))
        end
        local parts = {}
        for _, ev in ipairs(rec.events) do
            parts[#parts + 1] = (ev.dir_in and "D<- " or "H-> ")
                              .. (ev.label or ev.kind)
        end
        pinfo.cols.info = (rec.events[1].dir_in and "[DEV] " or "[HOST] ")
                        .. table.concat(parts, " | ")
    end
end

-- =============================================================== registration
local function register()
    local bulk = DissectorTable.get("usb.bulk")
    if bulk then
        bulk:add(0xFF,   pd)
        bulk:add(0xFFFF, pd)
    end
    local prod = DissectorTable.get("usb.product")
    if prod then
        prod:add(0x0E8D2000, pd)
        prod:add(0x0E8D2001, pd)
        prod:add(0x0E8D0003, pd)
    end
end
register()

-- =============================================================== flash summary (V5)
-- hw_code -> SoC name (from mtkclient brom_config; first listed part number).
local CHIPS = {
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

local sf5_part = Field.new("xflash.partition")
local sf5_len  = Field.new("xflash.length")
local sf5_kind = Field.new("xflash.kind")
local sf5_cmd  = Field.new("xflash.cmd")
local sf5_text = Field.new("xflash.text")

-- byte count -> GiB/MiB/KiB (storage & RAM figures are large)
local function hsize(n)
    if n >= 0x40000000 then return string.format("%.2f GiB", n / 0x40000000) end
    if n >= 0x100000   then return string.format("%.1f MiB", n / 0x100000)   end
    if n >= 0x400      then return string.format("%.1f KiB", n / 0x400)      end
    return tostring(n) .. " B"
end
-- true if `s` reports a non-zero size for `pat` (a device queries every storage
-- type; only the one actually present has non-zero fields)
local function present(s, pat)
    local v = tonumber((s:match(pat)) or "0", 16)
    return v and v > 0
end

local function show_flash_summary_v5()
    local acc, errors = {}, 0
    local cmdhist, ncmd = {}, 0
    local dev = {}
    local tap = Listener.new(nil, "xflash")
    local win = TextWindow.new("MTK DA (V5 XFlash) \226\128\148 session summary")

    function tap.reset() acc, errors, cmdhist, ncmd, dev = {}, 0, {}, 0, {} end
    function tap.packet()
        local ki = sf5_kind(); if not ki then return end
        local kind = tostring(ki.value)

        local c = sf5_cmd()
        if c then cmdhist[c.value] = (cmdhist[c.value] or 0) + 1; ncmd = ncmd + 1 end

        local t = sf5_text()
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
            local p = sf5_part() and tostring(sf5_part().value) or "?"
            local a = acc[p] or { w = 0, c = 0 }
            a.w = a.w + (sf5_len() and sf5_len().value or 0)
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
            out[#out + 1] = string.format("  Storage: eMMC%s\n", u and (" \226\128\148 user " .. hsize(u)) or "")
            out[#out + 1] = "           " .. dev.emmc .. "\n"
        elseif dev.ufs then
            local l = tonumber((dev.ufs:match("lu0=0x(%x+)")) or "", 16)
            out[#out + 1] = string.format("  Storage: UFS%s\n", l and (" \226\128\148 LU0 " .. hsize(l)) or "")
            out[#out + 1] = "           " .. dev.ufs .. "\n"
        elseif dev.nand then
            out[#out + 1] = "  Storage: NAND \226\128\148 " .. dev.nand .. "\n"
        end
        if dev.ram then
            local d = tonumber((dev.ram:match("DRAM base=0x%x+ size=0x(%x+)")) or "", 16)
            out[#out + 1] = string.format("  DRAM:    %s\n", d and hsize(d) or dev.ram)
        end
        if not dev.chip and not dev.emmc and not dev.ufs then
            out[#out + 1] = "  (no device info \226\128\148 device\226\134\146host direction not recorded in this capture)\n"
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
                    and string.format("  \226\128\148  %d%% of %s", math.floor(a.w / total * 100), human(total)) or ""
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

-- =============================================================== flash summary (V6)
local sf6_part    = Field.new("xmlflash.partition")
local sf6_kind    = Field.new("xmlflash.kind")
local sf6_datalen = Field.new("xmlflash.data_length")

local function show_flash_summary_v6()
    local acc, errors = {}, 0
    local tap = Listener.new(nil, "xmlflash")
    local win = TextWindow.new("MTK XMLFlash (V6) \226\128\148 flash summary")

    function tap.reset() acc, errors = {}, 0 end
    function tap.packet()
        local ki = sf6_kind();  if not ki then return end
        local kind = tostring(ki.value)
        if kind == "data" then
            local p = sf6_part()
            if p then
                local name = tostring(p.value)
                local a = acc[name] or { w = 0, c = 0 }
                local dl = sf6_datalen()
                a.w = a.w + (dl and dl.value or 0)
                a.c = a.c + 1
                acc[name] = a
            end
        elseif kind == "err" then
            errors = errors + 1
        end
    end
    function tap.draw()
        local names, out = {}, {}
        for p in pairs(acc) do names[#names + 1] = p end
        table.sort(names)
        for _, p in ipairs(names) do
            local a = acc[p]
            out[#out + 1] = string.format("%-20s %10s in %d chunks\n",
                                          p, human(a.w), a.c)
        end
        if errors > 0 then
            out[#out + 1] = string.format("\n! %d error(s) seen\n", errors)
        end
        if #out == 0 then
            out[1] = "No flash data transfers seen in this capture.\n"
        end
        win:set(table.concat(out))
        tap:remove()
    end
    win:set_atclose(function() tap:remove() end)
    retap_packets()
end

if gui_enabled() then
    register_menu("MTK DA/Flash summary (V5 XFlash)",  show_flash_summary_v5, MENU_TOOLS_UNSORTED)
    register_menu("MTK DA/Flash summary (V6 XMLFlash)", show_flash_summary_v6, MENU_TOOLS_UNSORTED)
end
