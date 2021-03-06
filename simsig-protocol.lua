-- Wireshark SimSig Protocol Dissector
-- Drop this file into your Wireshark Plugins Directory to use
--   * On Linux: ~/.local/lib/wireshark/plugins
--   * On Windows: %APPDATA%\Wireshark\Plugins

local proto = Proto("simsig", "SimSig Protocol")

--------------------
-- Command fields --
--------------------
-- Headers/inferred
local is_client_f = ProtoField.bool("simsig.is_client", "Client command")
local seq_f = ProtoField.uint8("simsig.seq", "Command sequence", base.DEC)
local crc_f = ProtoField.uint8("simsig.crc.value", "CRC", base.HEX)
--local crcvalid_f = ProtoField.bool("simsig.crc.valid", "CRC Valid")

local msgtype_f = ProtoField.string("simsig.type", "Command type")

-- Ping status
local ping_time_f = ProtoField.absolute_time("simsig.ping_time", "Ping/Pong Time")
local latency_f = ProtoField.relative_time("simsig.latency", "Latency")

-- Clock Settings
local sim_time_f = ProtoField.string("simsig.clock.time", "Sim Clock Time")
local speed_f = ProtoField.uint8("simsig.clock.speed", "Sim Clock Speed")
local pause_f = ProtoField.bool("simsig.clock.paused", "Sim Clock Paused")

local sim_setting_f = ProtoField.string("simsig.sim_setting", "Sim setting")

-- General Identifiers, all generally use 0-index of position in save game file. -1 for when unset.
local descr_f = ProtoField.string("simsig.description", "Berth Description")
local berth_f = ProtoField.int16("simsig.berth_id", "Berth ID")
local route_f = ProtoField.int16("simsig.route_id", "Route ID")

-- Signal information
local sig_f = ProtoField.int16("simsig.signal.id", "Signal ID")

local sig_state_f = ProtoField.uint8("simsig.signal.state", "Signal State", base.HEX)
local sig_state_auto_f = ProtoField.bool("simsig.signal.auto_on", "Auto Signal Enabled", 8, nil, 0x1)
local sig_state_proving_f = ProtoField.bool("simsig.signal.proving", "Signal Proving", 8, nil, 0x2)

local sig_aspect_f = ProtoField.uint8("simsig.signal.aspect", "Signal Aspect", base.DEC_HEX,
  { [0] = "Red", "Shunt", "Single Yellow", "Flashing Single Yellow",
    "Double Yellow", "Flashing Double Yellow", "Green" })

local sig_rem_f = ProtoField.uint8("simsig.signal.reminders", "Reminders Applied", base.HEX)
local sig_rem_gen_f = ProtoField.bool("simsig.signal.reminders.gen", "General", 8, nil, 0x1)
local sig_rem_iso_f = ProtoField.bool("simsig.signal.reminders.iso", "Isolation", 8, nil, 0x2)
local sig_aut_gen_f = ProtoField.bool("simsig.signal.reminders.gen_auto", "General Auto", 8, nil, 0x4)
local sig_aut_iso_f = ProtoField.bool("simsig.signal.reminders.iso_auto", "Isolation Auto", 8, nil, 0x8)
local sig_rem_unk_f = ProtoField.bool("simsig.signal.reminders.unknown", "Unknown", 8, nil, 0x30)
local sig_rep_gen_f = ProtoField.bool("simsig.signal.reminders.gen_repl", "General Replacement", 8, nil, 0x40)
local sig_rep_iso_f = ProtoField.bool("simsig.signal.reminders.iso_repl", "Isolation Replacement", 8, nil, 0x80)

-- Route setting
local rem_override_f = ProtoField.bool("simsig.reminder_override", "Reminder Override", 8, nil, 0x1)

-- Messages
local message_type_f = ProtoField.uint8("simsig.message.type", "Message Type")
local message_text_f = ProtoField.string("simsig.message.text", "Message Text")

-- Workstation Control
local workstation_f = ProtoField.int16("simsig.workstation_id", "Workstation ID")
local workstation_control_f = ProtoField.bool("simsig.workstation.taken", "Workstation Control Taken")

-- Debug
local unknown_msg_f = ProtoField.bool("simsig.todo_msg", "Command type needs decoding")
local unknown_f = ProtoField.bool("simsig.todo", "Command body needs decoding")

proto.fields = {is_client_f, seq_f, crc_f, msgtype_f,
                sim_time_f, speed_f, pause_f,
                ping_time_f, latency_f,
                sim_setting_f, descr_f, berth_f, route_f,
                sig_f, sig_state_f, sig_state_auto_f, sig_state_proving_f, sig_aspect_f,
                sig_rem_f, sig_rem_unk_f, sig_rem_gen_f, sig_rem_iso_f,
                sig_aut_gen_f, sig_aut_iso_f, sig_rep_gen_f, sig_rep_iso_f,
                rem_override_f,
                message_type_f, message_text_f,
                workstation_f, workstation_control_f,
                unknown_msg_f, unknown_f}

-------------
-- Helpers --
-------------
local function buf_a_int(buf)
  return tonumber(buf:string(), 16)
end

local function delphi_datetime_to_unix(datetime)
  local epoch = 25569                        -- 1970-01-01 00:00:00
  local s = (tonumber(datetime)-epoch)*86400 -- days to seconds
  local ns = math.fmod(s, 1) * 1000000000    -- extract sub-seconds to nanoseconds
  return NSTime.new(math.floor(s), ns)
end

-- Test whether command is from client or server based upon src port.
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

local frame_time_f = Field.new("frame.time")
local function pingpong(desc)
  return function(tree, buf)
    local time = delphi_datetime_to_unix(buf:string())
    tree:add(ping_time_f, buf, time)
    local delta = frame_time_f().value - time
    tree:add(latency_f, delta):set_generated()
    return desc
  end
end

-- SimSig passes object identifiers encoded as string hex, they are 2 bytes long.
-- Parse the given TvbRange into the native uint16 and store to given field
local function add_id(tree, buf, field, prepend)
  local val = buf_a_int(buf(0,4))
  local t = tree:add(field, buf(0,4), val)
  if prepend then
    t:prepend_text(prepend .. " ")
  end
  return val
end

local function basic_cmd(descr, field)
  return function(tree, buf)
    local id = add_id(tree, buf, field)
    return descr .. ": " .. id
  end
end

local function signal_cmd(descr)
  return basic_cmd(descr, sig_f)
end

local function unknown(tree, buf, descr)
  if not descr then
    descr = "Unknown command body content"
  end
  if buf then
    tree:add(unknown_f, buf, true, descr, ("[%d bytes]"):format(buf:len()))
  end
end

-- Default command parser for when the type of command is known, but the body content syntax is not.
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
    return descr
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

  -- Clock, sent by server, clients respond with prior state
  -- Sim speed in tick/s (or x) is 500/speed
  ["zA"] = function(tree, buf)
    local time = os.date("!%T", buf_a_int(buf(0,8)))
    local speed = buf_a_int(buf(8,8))
    local pause = buf_a_int(buf(16,1))
    tree:add(sim_time_f, buf(0,8), time)
    tree:add(speed_f, buf(8,8), speed):append_text(string.format(" (%.2fx)", 500/speed))
    tree:add(pause_f, buf(16,1), pause)

    local pause_s = pause and "paused" or "running"
    return string.format("Clock update, %s, %s, %.2fx", pause_s, time, 500/speed)
  end,

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

  ["sS"] = function(tree, buf)
    local id = add_id(tree, buf(0,4), sig_f)
    local rems_val = buf_a_int(buf(4,2))
    local rems = tree:add(sig_rem_f, buf(4,2), rems_val)
    rems:add(sig_rep_iso_f, buf(4,2), rems_val)
    rems:add(sig_rep_gen_f, buf(4,2), rems_val)
    rems:add(sig_rem_unk_f, buf(4,2), rems_val)
    rems:add(sig_aut_iso_f, buf(4,2), rems_val)
    rems:add(sig_aut_gen_f, buf(4,2), rems_val)
    rems:add(sig_rem_iso_f, buf(4,2), rems_val)
    rems:add(sig_rem_gen_f, buf(4,2), rems_val)

    local state_val = buf_a_int(buf(6,1))
    local state = tree:add(sig_state_f, buf(6,1), state_val)
    state:add(sig_state_auto_f, buf(6,1), state_val)
    state:add(sig_state_proving_f, buf(6,1), state_val)

    local aspect_val = buf_a_int(buf(7,1))
    local aspect = tree:add(sig_aspect_f, buf(7,1), aspect_val)

    local route = add_id(tree, buf(8,4), route_f)

    unknown(tree, buf(12,2))
    unknown(tree, buf(14,4))
    return string.format("Update signal: %s", id)
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
    unknown(tree, buf(8,1))
    tree:add(rem_override_f, buf(9,1), buf_a_int(buf(9,1)))
    unknown(tree, buf(10,1))
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
    tree:add(message_type_f, buf(0,2), buf_a_int(buf(0,2)))
    local text = buf(2):string()
    tree:add(message_text_f, buf(2), text)
    return ("Simulation message (%s)"):format(text)
  end,

  -- Workstation Control
  ["WA"] = basic_cmd("Take Workstation Control", workstation_f),
  ["WB"] = basic_cmd("Cease Workstation Control", workstation_f),
  ["WC"] = function(tree, buf)
    local id = add_id(tree, buf, workstation_f)
    local bool = buf_a_int(buf(4,1))
    tree:add(workstation_control_f, buf(5,1), bool)
    local text = if bool then "taken" else "ceased" end
    return ("Workstation control %s for workstation id: %s"):format(text, id)
  end,

  default = unknown_body(),
}

-- Takes a command and parses with appropriate parser
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

    local header = ptree:add(buf(0, 3), "Header")
    header:add(is_client_f, not server):set_generated()
    if buf(0, 1):string() == "!" then
      header:add(seq_f, buf(1, 1), buf(1, 1):uint() - 33)
      header:add(crc_f, buf(2, 1))
      buf = buf(3, len-3)
    end

    info = msgtypes:process(ptree, buf)
  end

  if npkts > 1 then
    info = n .. " batched commands"
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

