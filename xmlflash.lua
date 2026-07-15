--[[
    MediaTek DA "XMLFlash" (V6) protocol dissector for Wireshark

    Wire format is identical to V5/XFlash:
        [ magic : u32 = 0xFEEEEEEF ][ type : u32 ][ length : u32 ][ payload ]
        type 1 = DT_PROTOCOL_FLOW    type 2 = DT_MESSAGE (+ 4-byte priority)

    V6 payloads are XML text / ASCII strings instead of binary opcodes:
      Host commands:   <?xml ...><da><command>CMD:XXX</command><arg>...</arg></da>
      Device replies:  "OK", "OK@0xNNN", "ERR!...", or XML in <host>...</host>
      Lifecycle:       CMD:START -> command -> OK -> negotiate -> data -> CMD:END -> CMD:START

    NOTE: This dissector registers on the SAME USB product IDs as xflash.lua (V5).
    Load ONE or the OTHER in your plugins folder, not both.
      V5 capture -> use xflash.lua      V6 capture -> use xmlflash.lua
]]--

if _G.__mtk_xmlflash_loaded then return end
_G.__mtk_xmlflash_loaded = true

local xf = Proto("xmlflash", "MTK DA XMLFlash V6")

-- ------------------------------------------------------------------ constants
local MAGIC     = 0xFEEEEEEF
local MAGIC_B   = string.char(0xEF, 0xEE, 0xEE, 0xFE)
local DT_FLOW   = 1
local DT_MSG    = 2
local HDR_LEN   = 12

-- ------------------------------------------------------------------ fields
local f = {
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
xf.fields = { f.magic, f.dtype, f.length, f.dir, f.kind, f.cmd, f.text,
              f.xml, f.part, f.progress, f.info, f.priority, f.data, f.datalen }

local pe_resync = ProtoExpert.new("xmlflash.resync", "Framing resync",
                                   expert.group.PROTOCOL, expert.severity.WARN)
xf.experts = { pe_resync }

-- USB field extractors (must be at load time)
local fe_ep   = Field.new("usb.endpoint_address")
local fe_bus  = Field.new("usb.bus_id")
local fe_dev  = Field.new("usb.device_address")
local fe_dlen = Field.new("usb.data_len")

-- ------------------------------------------------------------------ helpers
local function u32(raw, off)
    local a, b, c, d = raw:byte(off + 1, off + 4)
    return a + b * 256 + c * 65536 + d * 16777216
end

local function human(n)
    if n >= 1048576 then return string.format("%.1f MB", n / 1048576)
    elseif n >= 1024 then return string.format("%.1f KB", n / 1024)
    else return tostring(n) .. " B" end
end

local function raw_to_tvb(raw)
    return ByteArray.new(raw, true):tvb("reassembled")
end

local function xml_get(s, tag)
    return s:match("<" .. tag .. ">(.-)</" .. tag .. ">") or ""
end

local function strip_null(s)
    return s:gsub("%z+$", "")
end

-- ------------------------------------------------------------------ sessions
local sessions = {}
local results  = {}

-- Wireshark calls this at the start of every dissection pass: initial load,
-- reload (Ctrl+R), and switching capture files. Without it the stateful
-- reassembly caches survive across loads, so a reload returns frames cached
-- under colliding packet numbers from the previous file and the OUT/IN state
-- machines resume mid-stream. Clearing here forces a clean re-parse.
function xf.init()
    sessions = {}
    results  = {}
end

local function get_session(pinfo)
    local ep_f, bus_f, dev_f = fe_ep(), fe_bus(), fe_dev()
    if not ep_f or not bus_f or not dev_f then return nil, false end
    local ep  = ep_f.value
    local dir_in = (bit.band(ep, 0x80) ~= 0)
    local key = string.format("%d-%d-%d", bus_f.value, dev_f.value,
                              bit.band(ep, 0x0F))
    if not sessions[key] then
        sessions[key] = {
            eps      = {},
            buf_out  = "",
            hdr_out  = nil,
            out_skip = 0,
            buf_in   = "",
            last_cmd = nil,
            partition = nil,
            upload   = nil,
        }
    end
    local sess = sessions[key]
    sess.eps[ep] = dir_in
    return sess, dir_in
end

-- ----------------------------------------------------------- frame classify
local function classify(sess, payload, dir_in)
    local text = strip_null(payload)
    local ev   = { dir_in = dir_in }

    -- ---- XML payloads --------------------------------------------------
    if text:sub(1, 1) == "<" then
        local cmd_raw = xml_get(text, "command")
        local cmd     = cmd_raw:gsub("^CMD:", "")
        ev.xml_text   = text

        if text:find("<da>") or text:find("<da ") then
            -- host command
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
                -- Readback (device->host): same framing as a download, so track
                -- it the same way. Without this, binary chunks that happen to
                -- start with a printable byte fall to the text heuristic.
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

    -- ---- text responses ------------------------------------------------
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

-- --------------------------------------------------------- OUT reassembly
local function feed_out(sess, raw, pkt, events)
    local real_len = #raw
    local df = fe_dlen()
    if df and df.value > 0 then real_len = df.value end

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
            events[#events + 1] = classify(sess, payload, false)
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
            events[#events + 1] = classify(sess, payload, false)
            sess.hdr_out = nil
            sess.buf_out = ""
        end
    end
end

-- ---------------------------------------------------------- IN reassembly
local function feed_in(sess, raw, pkt, events)
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
                events[#events + 1] = classify(sess, payload, true)
            end
        end
    end
end

-- --------------------------------------------------------- tree rendering
local function render_event(tree, ev, buf)
    local sub = tree:add(xf, buf())
    sub:add(f.dir,  buf(), ev.dir_in and "device" or "host")
    sub:add(f.kind, buf(), ev.kind)

    if ev.cmd       then sub:add(f.cmd,      buf(), ev.cmd) end
    if ev.partition then sub:add(f.part,     buf(), ev.partition) end
    if ev.xml_text  then sub:add(f.xml,      buf(), ev.xml_text:sub(1, 2000)) end
    if ev.text      then sub:add(f.text,     buf(), ev.text:sub(1, 500)) end
    if ev.data_len  then sub:add(f.datalen,  buf(), ev.data_len) end

    if ev.progress_text then sub:add(f.progress, buf(), ev.progress_text) end
    if ev.priority_val  then sub:add(f.priority, buf(), ev.priority_val) end

    local info = ev.label or ev.kind
    sub:add(f.info, buf(), info)
    sub:set_text(string.format("XMLFlash %s: %s",
        ev.dir_in and "DEV" or "HOST", info))
    return sub
end

-- ------------------------------------------------------------- dissector
function xf.dissector(buf, pinfo, tree)
    local sess, dir_in = get_session(pinfo)
    if not sess then return 0 end

    local pkt    = pinfo.number
    local events = results[pkt]

    if not events then
        events = {}
        local raw = buf:raw()
        if dir_in then
            feed_in(sess, raw, pkt, events)
        else
            feed_out(sess, raw, pkt, events)
        end
        if #events > 0 then results[pkt] = events end
    end

    if not events or #events == 0 then return 0 end

    pinfo.cols.protocol = "XMLFlash"

    for _, ev in ipairs(events) do
        local sub = render_event(tree, ev, buf)
        sub:add_expert_info(expert.group.SEQUENCE, expert.severity.CHAT,
            (ev.dir_in and "D<- " or "H-> ") .. (ev.label or ev.kind))
    end

    local parts = {}
    for _, ev in ipairs(events) do
        parts[#parts + 1] = (ev.dir_in and "D<- " or "H-> ")
                          .. (ev.label or ev.kind)
    end
    pinfo.cols.info = (events[1].dir_in and "[DEV] " or "[HOST] ")
                    .. table.concat(parts, " | ")
end

-- ----------------------------------------------------------- registration
local function register()
    local bulk = DissectorTable.get("usb.bulk")
    if bulk then
        bulk:add(0xFF,   xf)
        bulk:add(0xFFFF, xf)
    end
    local prod = DissectorTable.get("usb.product")
    if prod then
        prod:add(0x0E8D2000, xf)
        prod:add(0x0E8D2001, xf)
        prod:add(0x0E8D0003, xf)
    end
end
register()

-- ----------------------------------------------------------- flash summary
local sf_part    = Field.new("xmlflash.partition")
local sf_kind    = Field.new("xmlflash.kind")
local sf_datalen = Field.new("xmlflash.data_length")

local function show_flash_summary()
    local acc, errors = {}, 0
    local tap = Listener.new(nil, "xmlflash")
    local win = TextWindow.new("MTK XMLFlash V6 \226\128\148 flash summary")

    function tap.reset() acc, errors = {}, 0 end
    function tap.packet()
        local ki = sf_kind();  if not ki then return end
        local kind = tostring(ki.value)
        if kind == "data" then
            local p = sf_part()
            if p then
                local name = tostring(p.value)
                local a = acc[name] or { w = 0, c = 0 }
                local dl = sf_datalen()
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
    register_menu("MTK XMLFlash/Flash summary", show_flash_summary,
                  MENU_TOOLS_UNSORTED)
end
