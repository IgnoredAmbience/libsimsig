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

-- Identifiers
local berth_f = ProtoField.uint16("simsig.berth_id", "Berth ID", base.DEC_HEX)
local descr_f = ProtoField.string("simsig.description", "Berth Description")

proto.fields = {is_client_f, seq_f, crc_f, msgtype_f, sim_setting_f, berth_f, descr_f}

-------------
-- Helpers --
-------------

-- Test whether message is from client or server based upon src port.
local src_port_f = Field.new("tcp.srcport")
function is_server()
  local src_port = src_port_f().value
  return src_port == 50505 or src_port == 50507
end

local function parse_version(buf, tree)
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

-- SimSig passes object identifiers encoded as string hex, they are 2 bytes long.
-- Parse the given TvbRange into the native uint16 and store to given field
local function parse_id(buf)
  return tonumber(buf(0,4):string(), 16)
end

-- Prints an object identity in decimal followed by hex
local function id_str(id)
  return string.format("%d (0x%.4x)", id, id)
end

-- Default message parser for when the type of message is known, but the body content syntax is not.
local function unknown_body(descr)
  return function(buf, tree, cmd)
    if buf then
      tree:add(proto, buf, "Unknown message body content", ("[%d bytes]"):format(buf:len()));
    end
    return ("%s (%s)"):format(descr, cmd)
  end
end

-------------------
-- Message types --
-------------------
local msgtypes = {
  -- ** Connection strings ** --
  ["iA"] = function(buf, tree)
    tree:add(proto, buf(0,4), "Client name:", buf(0,4):string())
    tree:add(proto, buf(4,1), "Unknown:", buf(4,1):string())
    return "Connect, version: "..parse_version(buf(5), tree)
  end,
  ["iD"] = function(buf, tree)
    return "Version: "..parse_version(buf, tree)
  end,

  -- ** Server ** --
  ["lA"] = function(buf, tree)
    local str = buf:string()
    tree:add(sim_setting_f, buf)
    return "Sim setting: " .. str
  end,
  ["MA"] = function(buf, tree)
    local str = buf:string()
    tree:add(sim_setting_f, buf)
    return "Sim setting: " .. str
  end,

  -- Updates
  ["sB"] = function(buf, tree)
    local id = parse_id(buf)
    tree:add(berth_f, buf(0,4), id)
    local desc = buf(4,4):string()
    tree:add(descr_f, buf(4,4))
    tree:add(proto, buf(8,8), "Unknown message body content [8 bytes]");
    tree:add(proto, buf(16,6), "Foreground Colour (ARS Status):", buf(16,6):string())
    tree:add(proto, buf(22,6), "Background Colour (ARS Status):", buf(22,6):string())
    tree:add(proto, buf(28,6), "Foreground Colour (Delay):", buf(28,6):string())
    tree:add(proto, buf(34,6), "Background Colour (Delay):", buf(34,6):string())
    tree:add(proto, buf(40,8), "Unknown message body content [8 bytes]");
    return ("Update berth: %s = %s"):format(id_str(id), desc)
  end,

  -- ** Client ** --
  -- Berth Requests
  ["BB"] = function(buf, tree)
    local id = parse_id(buf)
    local desc = buf(4,4):string()
    tree:add(berth_f, buf(0,4), id)
    tree:add(descr_f, buf(4,4))
    return ("Interpose berth: %s = %s"):format(id_str(id), desc)
  end,
  ["BC"] = function(buf, tree)
    local id = parse_id(buf)
    tree:add(berth_f, buf, id)
    return "Cancel berth: " .. id_str(id)
  end,

  -- Signals
  ["SA"] = unknown_body("Set route"),
  ["zD"] = unknown_body("Cancel route"),
  ["SB"] = unknown_body("Apply isolation reminder to signal"),
  ["SC"] = unknown_body("Remove isolation reminder from signal"),
  ["SD"] = unknown_body("Apply general reminder to signal"),
  ["SE"] = unknown_body("Remove general reminder from signal"),
  -- Auto buttons
  ["SF"] = unknown_body("Set signal auto"),
  ["SG"] = unknown_body("Cancel signal auto"),
  ["SH"] = unknown_body("Apply isolation reminder to auto button"),
  ["SI"] = unknown_body("Apply general reminder to auto button"),
  ["SJ"] = unknown_body("Remove isolation reminder from auto button"),
  ["SK"] = unknown_body("Remove general reminder from auto button"),
  -- Replacement buttons
  ["SP"] = unknown_body("Cancel signal replacement"),
  ["SQ"] = unknown_body("Set signal replacement"),
  ["SR"] = unknown_body("Apply isolation reminder to replacement button"),
  ["SS"] = unknown_body("Apply general reminder to replacement button"),
  ["ST"] = unknown_body("Remove isolation reminder from replacement button"),
  ["SU"] = unknown_body("Remove general reminder from replacement button"),

  -- Points Setting
  ["PB"] = unknown_body("Key points normal"),
  ["PC"] = unknown_body("Key points reverse"),
  ["PD"] = unknown_body("Apply reminder to points"),
  ["PE"] = unknown_body("Remove reminder from points"),

  -- Refresh State
  ["iB"] = unknown_body("Request refresh object state"),

  -- Messages
  ["mA"] = function(buf, tree)
    local text = buf(2):string()
    tree:add(proto, buf(0, 2), "Simulation message type:", buf(0, 2):string())
    tree:add(proto, buf(2), "Message content:", text)
    return ("Simulation message (%s)"):format(text)
  end,

  default = unknown_body("Unknown command"),
}

-- Takes a message and parses with appropriate parser
function msgtypes:process(buf, tree)
  local cmd = buf(0, 2)
  local f = self[cmd:string()] or self.default
  local ttree = tree:add(msgtype_f, cmd)

  if buf:len() > 2 then
    buf = buf(2)
  else
    buf = nil
  end
  local msgname = f(buf, tree, cmd:string())
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

    info = msgtypes:process(buf, ptree)
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

