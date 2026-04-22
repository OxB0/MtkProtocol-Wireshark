-- MediaTek XFlash - 

local xf
if not _G.mtk_xf_proto then
    xf = Proto("xflash", "MTK XFlash")
    _G.mtk_xf_proto = xf
    local f = xf.fields
    f.magic  = ProtoField.uint32("xflash.magic", "Magic", base.HEX)
    f.type   = ProtoField.uint32("xflash.type", "Type", base.DEC, { [1] = "Flow/Command", [2] = "DA Log Message" })
    f.length = ProtoField.uint32("xflash.length", "Payload Length", base.DEC)
    f.cmd    = ProtoField.uint32("xflash.cmd", "Command/Status ID", base.HEX)
    f.data   = ProtoField.bytes("xflash.data", "Data Payload")
    f.text   = ProtoField.string("xflash.text", "Log Message")
else
    xf = _G.mtk_xf_proto
end

-- --- 1. COMMAND MAP ---
local CMDS = {
 [0x00000000] = "STATUS_OK",
    [0x434E5953] = "SyncSignal",
    [0xFEEEEEEF] = "Magic",
    [0x010000] = "Unknown",
    [0x010001] = "Download",
    [0x010002] = "Upload",
    [0x010003] = "Format",
    [0x010004] = "WriteData",
    [0x010005] = "ReadData",
    [0x010006] = "FormatPartition",
    [0x010007] = "Shutdown",
    [0x010008] = "BootTo",
    [0x010009] = "DeviceCtrl",
    [0x01000A] = "InitExtRam",
    [0x01000B] = "SwitchUsbSpeed",
    [0x01000C] = "ReadOtpZone",
    [0x01000D] = "WriteOtpZone",
    [0x01000E] = "WriteEfuse",
    [0x01000F] = "ReadEfuse",
    [0x010010] = "NandBmtRemark",
    [0x010011] = "SramWriteTest",
    [0x010100] = "SetupEnvironment",
    [0x010101] = "SetupHwInitParams",
    [0x020001] = "SetBmtPercentage",
    [0x020002] = "SetBatteryOpt",
    [0x020003] = "SetChecksumLevel",
    [0x020004] = "SetResetKey",
    [0x020005] = "SetHostInfo",
    [0x020006] = "SetMetaBootMode",
    [0x020007] = "SetEmmcHwresetPin",
    [0x020008] = "SetGenerateGpx",
    [0x020009] = "SetRegisterValue",
    [0x02000A] = "SetExternalSig",
    [0x02000B] = "SetRemoteSecPolicy",
    [0x02000C] = "SetAllInOneSig",
    [0x02000D] = "SetRscInfo",
    [0x02000E] = "SetRebootMode",
    [0x02000F] = "SetCertFile",
    [0x020010] = "SetUpdateFw",
    [0x020011] = "SetUfsConfig",
    [0x020012] = "SetDynamicPartMap",
    [0x040001] = "GetEmmcInfo",
    [0x040002] = "GetNandInfo",
    [0x040003] = "GetNorInfo",
    [0x040004] = "GetUfsInfo",
    [0x040005] = "GetDaVersion",
    [0x040006] = "GetExpireData",
    [0x040007] = "GetPacketLength",
    [0x040008] = "GetRandomId",
    [0x040009] = "GetPartitionTblCata",
    [0x04000A] = "GetConnectionAgent",
    [0x04000B] = "GetUsbSpeed",
    [0x04000C] = "GetRamInfo",
    [0x04000D] = "GetChipId",
    [0x04000E] = "GetOtpLockStatus",
    [0x04000F] = "GetBatteryVoltage",
    [0x040010] = "GetRpmbStatus",
    [0x040011] = "GetExpireDate",
    [0x040012] = "GetDramType",
    [0x040013] = "GetDevFwInfo",
    [0x040014] = "GetHrid",
    [0x040015] = "GetErrorDetail",
    [0x040016] = "SlaEnabledStatus",
    [0x080001] = "StartDlInfo",
    [0x080002] = "EndDlInfo",
    [0x080003] = "ActLockOtpZone",
    [0x080004] = "DisableEmmcHwresetPin",
    [0x080005] = "CcOptionalDownloadAct",
    [0x080007] = "DaStorLifeCycleCheck",
    [0x080008] = "DisableSparseErase",
    [0x0E0000] = "UnknownCtrlCode",
    [0x0E0001] = "CtrlStorageTest",
    [0x0E0002] = "CtrlRamTest",
    [0x0E0003] = "DeviceCtrlReadRegister",
    [0x0F0000] = "ExtAck",
    [0x0F0001] = "ExtSetupDaCtx",
    [0x0F0002] = "ExtReadMem",
    [0x0F0003] = "ExtWriteMem",
    [0x0F0004] = "ExtReadRegister",
    [0x0F0005] = "ExtWriteRegister",
    [0x0F0006] = "ExtKeyDerive",
    [0x0F0007] = "ExtSej",
    [0x0F0008] = "ExtRpmbInit",
    [0x0F0009] = "ExtRpmbRead",
    [0x0F000A] = "ExtRpmbWrite",
    -- Error Codes
    [0xC0010001] = "ERR_GENERIC",
    [0xC0010005] = "ERR_PROTOCOL",
    [0xC0030002] = "ERR_DA_FILE_INVALID"
}

-- --- COMMANDS EXPECTING DATA RESPONSES ---
local DATA_RESP_COMMANDS = {
    [0x01000E] = { name = "Efuse WRITE", count = 2 },
    [0x01000F] = { name = "Efuse READ",  count = 2 },
    [0x040004] = { name = "GetUfsInfo",  count = 1 },
    [0x040001] = { name = "GetEmmcInfo", count = 1 },
    [0x040002] = { name = "GetNandInfo", count = 1 },
    [0x040003] = { name = "GetNorInfo",  count = 1 },
    [0x040007] = { name = "GetPacketLength",   count = 1 },
    [0x04000D] = { name = "GetChipId",   count = 1 },
    [0x040014] = { name = "GetHrid",     count = 1 },
}

-- ---  STATE TRACKING ---
local stream_buffers = { host = "", dev = "" }
local pkt_info_map = {} 
local pkt_expert_map = {}
local active_context = nil 
local resp_remaining = 0

function xf.init()
    stream_buffers = { host = "", dev = "" }
    pkt_info_map = {}
    pkt_expert_map = {}
    active_context = nil
    resp_remaining = 0
end

-- Helper to format hex strings
local function get_hex_string(buffer, start_pos, length)
    if length <= 0 then return "" end
    local hex_parts = {}
    local limit = math.min(length, 64)
    for i = 0, limit - 1 do
        table.insert(hex_parts, string.format("%02X", buffer:byte(start_pos + i)))
    end
    local res = table.concat(hex_parts)
    if length > 64 then res = res .. "..." end
    return res
end

-- ---  SCANNER ---
local function aggressive_scan(dir_key, is_host)
    local summaries = {}
    local findings = {}
    
    while true do
        local buf = stream_buffers[dir_key]
        if #buf < 4 then break end

        local m_start = buf:find("\xef\xee\xee\xfe", 1, true)
        if not m_start then
            stream_buffers[dir_key] = buf:sub(-3)
            break
        end

        if m_start > 1 then
            buf = buf:sub(m_start)
            stream_buffers[dir_key] = buf
        end

        if #buf < 12 then break end 
        
        local p_type = buf:byte(5) + (buf:byte(6) * 256)
        local b9, b10, b11, b12 = buf:byte(9, 12)
        local body_len = b9 + (b10 * 256) + (b11 * 65536) + (b12 * 16777216)
        local total_len = 12 + body_len

        if p_type == 2 then
            -- LOG MESSAGE
            if #buf >= total_len then
                local log_text = "LOG: " .. buf:sub(13, 12 + body_len):gsub("[%c]", "")
                table.insert(summaries, log_text:sub(1, 30))
                table.insert(findings, log_text)
                stream_buffers[dir_key] = buf:sub(total_len + 1)
            else break end

        elseif p_type == 1 then
            -- COMMAND/DATA
            if #buf < 16 then break end 
            
            local c1, c2, c3, c4 = buf:byte(13, 16)
            local cid = c1 + (c2 * 256) + (c3 * 65536) + (c4 * 16777216)
            
            local name = CMDS[cid]

            -- If Host sends a command that expects data, set the context and the counter
            if is_host and DATA_RESP_COMMANDS[cid] then
                active_context = DATA_RESP_COMMANDS[cid].name
                resp_remaining = DATA_RESP_COMMANDS[cid].count
            end

            -- Identify Data blocks if counter > 0
            if active_context and resp_remaining > 0 then
                -- A data block usually has CID 0 (STATUS_OK) or CID FEEEEEEF but a significant body length
                if (cid == 0 or cid == 0xFEEEEEEF) and body_len > 4 then
                    if active_context:find("Efuse") then
                        if body_len == 244 or body_len == 248 then
                            name = string.format("[%s] Yield Argument", active_context)
                        else
                            name = string.format("[%s] Efuse Argument", active_context)
                        end
                    else
                        name = string.format("[%s] Response Data", active_context)
                    end
                    -- Use up one credit from the counter
                    resp_remaining = resp_remaining - 1
                end
            end

            -- Fallback to Hex if not a recognized command and not a tracked response
            if not name then
                name = get_hex_string(buf, 13, body_len)
            end

            if #buf >= total_len then
                table.insert(summaries, name)
                table.insert(findings, name .. string.format(" (Len: %d)", body_len))
                stream_buffers[dir_key] = buf:sub(total_len + 1)
            else break end
        else
            stream_buffers[dir_key] = buf:sub(2) -- Junk
        end
    end
    return summaries, findings
end

-- ---  DISSECTOR ---
function xf.dissector(tvb, pinfo, root)
    if tvb:len() == 0 then return end
    local is_host = (tostring(pinfo.src) == "host" or not tostring(pinfo.src):find("%."))
    local dir_key = is_host and "host" or "dev"
    local prefix = is_host and "[HOST] " or "[DEV] "

    if not pinfo.visited then
        stream_buffers[dir_key] = stream_buffers[dir_key] .. tvb():raw()
        local summaries, findings = aggressive_scan(dir_key, is_host)
        if #summaries > 0 then 
            pkt_info_map[pinfo.number] = table.concat(summaries, " | ") 
            pkt_expert_map[pinfo.number] = findings
        end
    end

    pinfo.cols.protocol = "XFLASH"
    local tree = root:add(xf, tvb, "MediaTek XFlash Analysis")
    
    if pkt_info_map[pinfo.number] then
        pinfo.cols.info = prefix .. pkt_info_map[pinfo.number]
        local experts = pkt_expert_map[pinfo.number]
        if experts then
            for _, msg in ipairs(experts) do
                tree:add_expert_info(expert.group.SEQUENCE, expert.severity.CHAT, msg)
            end
        end
    else
        -- Clean hex snippet for unidentified data
        local raw = tvb():raw()
        local hex_snip = ""
        local limit = math.min(#raw, 32)
        for i = 1, limit do hex_snip = hex_snip .. string.format("%02X", raw:byte(i)) end
        if #raw > 32 then hex_snip = hex_snip .. "..." end
        pinfo.cols.info = prefix .. hex_snip
    end
end

-- ---  REGISTRATION ---
local function register()
    local tables = {"usb.bulk", "usb.data", "usbcom.data"}
    for _, name in ipairs(tables) do
        local t = DissectorTable.get(name)
        if t then t:add(0xFFFF, xf) end
    end
    local usb_prod = DissectorTable.get("usb.product")
    if usb_prod then
        usb_prod:add(0x0E8D2000, xf)
        usb_prod:add(0x0E8D0003, xf)
    end
end
register()