-- Wireshark SimSig Protocol Dissector
-- Drop this file into your Wireshark Plugins Directory to use
--   * On Linux: ~/.local/lib/wireshark/plugins
--   * On Windows: %APPDATA%\Wireshark\Plugins

local proto = Proto("simsig", "SimSig Protocol")

-- Message fields
local seq = ProtoField.uint8("simsig.seq", "Message sequence", base.DEC)
local crc = ProtoField.uint8("simsig.crc.value", "CRC", base.HEX)
--local crcvalid = ProtoField.bool("simsig.crc.valid", "CRC Valid")
local msgtype = ProtoField.string("simsig.type", "Message type", base.ASCII)
local msgs = ProtoField.uint8("simsig.msg_count", "Message count")

proto.fields = {seq, crc, msgtype, msgs}

-- Message types
local function unknown_body(descr)
  return function(buf, tree, cmd)
    tree:add(proto, buf, "Unknown message body content", ("[%d bytes]"):format(buf:len()));
    return ("%s (%s)"):format(descr, cmd)
  end
end

local msgtypes = {
  -- Connection strings
  ["iA"] = function(buf, tree)
    tree:add(proto, buf(0,4), "Client name:", buf(0,4):string())
    tree:add(proto, buf(4,1), "Unknown:", buf(4,1):string())
    return "Connect, version: "..parse_version(buf(5), tree)
  end,
  ["iD"] = function(buf, tree)
    return "Version: "..parse_version(buf, tree)
  end,

  ["MA"] = function(buf, tree)
    local str = buf:string()
    tree:add(proto, buf, "Sim setting:", str)
    return "Sim setting: " .. str
  end,

  -- Berth Requests
  ["BB"] = unknown_body("Interpose berth"),
  ["BC"] = unknown_body("Cancel berth"),

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
    tree:add(proto, buf(0, 2), "Simulation message type:", buf(0, 2):string())
    tree:add(proto, buf(2), "Message content:", buf(2):string())
    return "Simulation message"
  end,

  default = unknown_body("Unknown command"),
}

function msgtypes:process(buf, tree)
  local cmd = buf(0, 2)
  local f = self[cmd:string()] or self.default
  local ttree = tree:add(msgtype, cmd)
  local msgname = f(buf(2), tree, cmd:string())
  tree:append_text(', ' .. msgname)
  return msgname
end

-- Helpers
function parse_version(buf, tree)
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

local src_port_f = Field.new("tcp.srcport")
function is_server()
  local src_port = src_port_f().value
  return src_port == 50505 or src_port == 50507
end

-- create a function to dissect it
function proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "SimSig"
  tree = tree:add(proto, buffer())
  local ptree = tree
  local info = nil

  local body = buffer():string()
  local _, npkts = body:gsub('|', '|')
  local n = 1
  for init, pkt, fin in body:gmatch("()([^|]+)()|") do
    local begin = init - 1
    local len = fin - init
    local buf = buffer(begin, len)

    if npkts > 1 then
      ptree = tree:add(proto, buf, "Message", n)
      n = n + 1
    end

    if buf(0, 1):string() == "!" then
      local header = ptree:add(proto, buf(0, 3), "Header")
      header:add(seq, buf(1, 1), buf(1, 1):uint() - 33)
      header:add(crc, buf(2, 1))
      buf = buf(3, len-3)
    end

    info = msgtypes:process(buf, ptree)
  end

  tree:add(msgs, npkts):set_generated()
  if npkts > 1 then
    info = "Batched messages"
  end
  pinfo.cols.info = (is_server() and "Server: " or "Client: ") .. info
end

-- Analysis Window for SimSig message types
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

-- Register all the custom functions
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(50505, proto)
tcp_table:add(50507, proto)

register_menu("SimSig/Message Types", menuable_tap, MENU_TOOLS_UNSORTED)

