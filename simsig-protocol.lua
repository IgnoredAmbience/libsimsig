-- Wireshark SimSig Protocol Dissector
-- Drop this file into your Wireshark Plugins Directory to use
--   * On Linux: ~/.local/lib/wireshark/plugins
--   * On Windows: %APPDATA%\Wireshark\Plugins

local proto = Proto("simsig", "SimSig Protocol")

--------------------
-- Message fields --
--------------------
local is_client_f = ProtoField.bool("simsig.is_client", "Client Message")
local seq_f = ProtoField.uint8("simsig.seq", "Message sequence", base.DEC)
local crc_f = ProtoField.uint8("simsig.crc.value", "CRC", base.HEX)
--local crcvalid_f = ProtoField.bool("simsig.crc.valid", "CRC Valid")

local msgtype_f = ProtoField.string("simsig.type", "Message type")
local sim_setting_f = ProtoField.string("simsig.sim_setting", "Sim setting")

-- General Identifiers
local descr_f = ProtoField.string("simsig.description", "Berth Description")
local berth_f = ProtoField.uint16("simsig.berth_id", "Berth ID", base.DEC_HEX)
local sig_f = ProtoField.uint16("simsig.sig_id", "Signal ID", base.DEC_HEX)

local ping_time_f = ProtoField.absolute_time("simsig.ping_time", "Ping/Pong Time")
local latency_f = ProtoField.relative_time("simsig.latency", "Latency")

-- Debug
local unknown_msg_f = ProtoField.bool("simsig.todo_msg", "Message type needs decoding")
local unknown_f = ProtoField.bool("simsig.todo", "Message body needs decoding")

proto.fields = {is_client_f, seq_f, crc_f, msgtype_f, sim_setting_f, descr_f, berth_f, sig_f,
                ping_time_f, latency_f,
                unknown_msg_f, unknown_f}

-------------
-- Helpers --
-------------

-- Test whether message is from client or server based upon src port.
local src_port_f = Field.new("tcp.srcport")
function is_server()
  local src_port = src_port_f().value
  return src_port == 50505 or src_port == 50507
end

local function parse_version(tree, buf)
  local ver, sim_ver, loader_ver, sim = buf:string():match("(([%d%.]+)/([%d%.]+)/(.+))")
  if sim_ver then
    local l = #sim_ver
    local k = #loader_ver
    tree:add(proto, buf(0,l), "Sim version:", sim_ver)
    tree:add(proto, buf(l+1,k), "Loader version:", loader_ver)
    tree:add(proto, buf(l+k+2), "Sim ID:", sim)
  end
  return ver
end

local function delphi_datetime_to_unix(datetime)
  local epoch = 25569                -- 1970-01-01 00:00:00
  local t = (tonumber(datetime)-epoch)*86400
  return NSTime.new(math.floor(t), ) -- days to seconds
end

local frame_time_f = Field.new("frame.time")
local function pingpong(desc)
  return function(tree, buf)
    local time = delphi_datetime_to_unix(buf:string())
    tree:add(ping_time_f, buf, time)
    local delta = frame_time_f().value - time
    tree:add(latency_f, delta)
    return desc
  end
end

-- SimSig passes object identifiers encoded as string hex, they are 2 bytes long.
-- Parse the given TvbRange into the native uint16 and store to given field
local function parse_id(buf)
  return tonumber(buf(0,4):string(), 16)
end

local function add_id(tree, buf, field, prepend)
  local val = parse_id(buf)
  local t = tree:add(field, buf(0,4), val)
  if prepend then
    t:prepend_text(prepend .. " ")
  end
  return val
end

local function signal_cmd(descr)
  return function(tree, buf)
    local id = add_id(tree, buf, sig_f)
    return descr .. ": " .. id
  end
end

local function unknown(tree, buf, descr)
  if not descr then
    descr = "Unknown message body content"
  end
  if buf then
    tree:add(unknown_f, buf, true, descr, ("[%d bytes]"):format(buf:len()))
  end
end

-- Default message parser for when the type of message is known, but the body content syntax is not.
local function unknown_body(descr)
  return function(tree, buf, cmd)
    unknown(tree, buf)
    local d = descr
    if not d then
      tree:add(unknown_msg_f, true):set_generated()
      d = "Unknown command"
    end
    return ("%s (%s)"):format(d, cmd)
  end
end

local function empty_body(descr)
  return function()
    return desc
  end
end

-------------------
-- Message types --
-------------------
local msgtypes = {
  -- ** Connection strings ** --
  ["iA"] = function(tree, buf)
    tree:add(proto, buf(0,4), "Client name:", buf(0,4):string())
    tree:add(proto, buf(4,1), "Unknown:", buf(4,1):string())
    return "Connect, version: "..parse_version(tree, buf(5))
  end,
  ["iD"] = function(tree, buf)
    return "Version: "..parse_version(tree, buf)
  end,
  ["iE"] = empty_body("Disconnect"),

  -- Ping/Pong
  ["zG"] = pingpong("Ping!"),
  ["zH"] = pingpong("Pong!"),

  -- ** Server ** --
  ["lA"] = function(tree, buf)
    local str = buf:string()
    tree:add(sim_setting_f, buf)
    return "Sim setting: " .. str
  end,
  ["MA"] = function(tree, buf)
    local str = buf:string()
    tree:add(sim_setting_f, buf)
    return "Sim setting: " .. str
  end,

  -- Updates
  ["sB"] = function(tree, buf)
    local id = add_id(tree, buf(0,4), berth_f)
    local desc = buf(4,4):string()
    tree:add(descr_f, buf(4,4))
    unknown(tree, buf(8,8))
    tree:add(proto, buf(16,6), "Foreground Colour (ARS Status):", buf(16,6):string())
    tree:add(proto, buf(22,6), "Background Colour (ARS Status):", buf(22,6):string())
    tree:add(proto, buf(28,6), "Foreground Colour (Delay):", buf(28,6):string())
    tree:add(proto, buf(34,6), "Background Colour (Delay):", buf(34,6):string())
    unknown(tree, buf(40,8))
    return ("Update berth: %s = %s"):format(id, desc)
  end,

  -- ** Client ** --
  -- Berth Requests
  ["BB"] = function(tree, buf)
    local id = add_id(tree, buf, berth_f)
    local desc = buf(4,4):string()
    tree:add(descr_f, buf(4,4))
    return ("Interpose berth: %s ← %s"):format(id, desc)
  end,
  ["BC"] = function(tree, buf)
    local id = add_id(tree, buf, berth_f)
    return "Cancel berth: " .. id
  end,

  -- Signals
  ["SA"] = function(tree, buf)
    local entry_sig = add_id(tree, buf, sig_f, "Entry")
    local exit_sig = add_id(tree, buf(4), sig_f, "Exit")
    unknown(tree, buf(8,3), "Unknown bitfield, possibly reminder override")
    local other_sig = add_id(tree, buf(11), sig_f, "Other")
    unknown(tree, buf(15))
    return string.format("Set route, %s → %s", entry_sig, exit_sig)
  end,
  ["zD"] = signal_cmd("Cancel route"),
  ["SB"] = signal_cmd("Apply isolation reminder to signal"),
  ["SC"] = signal_cmd("Remove isolation reminder from signal"),
  ["SD"] = signal_cmd("Apply general reminder to signal"),
  ["SE"] = signal_cmd("Remove general reminder from signal"),
  -- Auto buttons
  ["SF"] = signal_cmd("Set signal auto"),
  ["SG"] = signal_cmd("Cancel signal auto"),
  ["SH"] = signal_cmd("Apply isolation reminder to auto button"),
  ["SI"] = signal_cmd("Apply general reminder to auto button"),
  ["SJ"] = signal_cmd("Remove isolation reminder from auto button"),
  ["SK"] = signal_cmd("Remove general reminder from auto button"),
  -- Replacement buttons
  ["SP"] = signal_cmd("Cancel signal replacement"),
  ["SQ"] = signal_cmd("Set signal replacement"),
  ["SR"] = signal_cmd("Apply isolation reminder to replacement button"),
  ["SS"] = signal_cmd("Apply general reminder to replacement button"),
  ["ST"] = signal_cmd("Remove isolation reminder from replacement button"),
  ["SU"] = signal_cmd("Remove general reminder from replacement button"),

  -- Points Setting
  ["PB"] = unknown_body("Key points normal"),
  ["PC"] = unknown_body("Key points reverse"),
  ["PD"] = unknown_body("Apply reminder to points"),
  ["PE"] = unknown_body("Remove reminder from points"),

  -- Refresh State
  ["iB"] = unknown_body("Request refresh object state"),

  -- ARS Control
  ["aA"] = unknown_body("Make Train ARS"),      -- xxxxDESC, response sim msgs type 04
  ["aB"] = unknown_body("Make Train Non-ARS"),  -- xxxxDESC, response sim msgs type 04
  ["aC"] = unknown_body("Is Train ARS?"),       -- xxxxDESC, response sim msgs type 04
  ["aE"] = unknown_body("Query ARS Status"),    -- xxxxDESC, response sim msgs type 04
  ["aF"] = unknown_body("Query ARS Timetable"), -- xxxxDESC, response sim msgs type 04

  -- Timetable
  ["tO"] = unknown_body("Timetable Request"),         -- DESC      BRTH
  ["tL"] = empty_body("Timetable Response Begin"),
  ["tM"] = unknown_body("Timetable Response Line"),   -- free text body, multiple rows, ends two empty?

  -- Messages
  ["mA"] = function(tree, buf)
    local text = buf(2):string()
    tree:add(proto, buf(0, 2), "Simulation message type:", buf(0, 2):string())
    tree:add(proto, buf(2), "Message content:", text)
    return ("Simulation message (%s)"):format(text)
  end,

  default = unknown_body(),
}

-- Takes a message and parses with appropriate parser
function msgtypes:process(tree, buf)
  local b = buf
  local cmd = b(0, 2)
  local f = self[cmd:string()] or self.default
  local ttree = tree:add(msgtype_f, cmd)

  if b:len() > 2 then
    b = b(2)
  else
    b = nil
  end
  local msgname = f(tree, b, cmd:string())
  tree:append_text(', ' .. msgname)
  return msgname
end

---------------------------------
-- The Dissector Main Function --
---------------------------------
function proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "SimSig"
  local info = 'ERROR, packet not parsed'

  local server = is_server()

  -- Use raw string function, as may contain extended ASCII characters that get converted to UTF8
  -- with :string(), and cause length mismatches due to wireshark lua bugs
  local body = buffer():raw()
  local _, npkts = body:gsub('|', '|')
  local n = 0
  for init, pkt, fin in body:gmatch("()([^|]+)()|") do
    n = n + 1
    local begin = init - 1
    local len = fin - init
    local buf = buffer(begin, len)

    local ptree = tree:add(proto, buffer(begin, len+1))
    if (npkts > 1) then
      ptree:append_text(string.format(" (Message %d of %d)", n, npkts))
    end

    if buf(0, 1):string() == "!" then
      local header = ptree:add(proto, buf(0, 3), "Header")
      header:add(seq_f, buf(1, 1), buf(1, 1):uint() - 33)
      header:add(crc_f, buf(2, 1))
      buf = buf(3, len-3)
    end

    info = msgtypes:process(ptree, buf)
    ptree:add(is_client_f, not server):set_generated()
  end

  if npkts > 1 then
    info = n .. " batched messages"
  end
  pinfo.cols.info = (server and "Server: " or "Client: ") .. info
end

----------------------------
-- Listeners for Analysis --
----------------------------
local type_f = Field.new("simsig.type")
local function menuable_tap()
  local tw = TextWindow.new("Message Type Counter")
  local tap = Listener.new(nil, "simsig")
  local types = {}

  local function remove()
    tap:remove()
  end
  tw:set_atclose(remove)

  function tap.packet(pinfo,tvb)
    local t = type_f().value
    local count = types[t] or 0
    types[t] = count + 1
  end

  function tap.draw(t)
    tw:clear()
    for typ,num in pairs(types) do
      tw:append(typ .. "\t" .. num .. "\n");
    end
  end

  function tap.reset()
    tw:clear()
    types = {}
  end

  -- Ensure that all existing packets are processed.
  retap_packets()
end

-------------------------
-- Plugin Registration --
-------------------------
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(50505, proto)
tcp_table:add(50507, proto)

register_menu("SimSig/Message Types", menuable_tap, MENU_TOOLS_UNSORTED)

