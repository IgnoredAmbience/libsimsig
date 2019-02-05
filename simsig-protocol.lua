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
local msgtypes = {
  -- Connection strings
  ["iA"] = function(buf, tree)
    tree:add(proto, buf(0,4), "Client name:", buf(0,4):string())
    tree:add(proto, buf(4,1), "Unknown:", buf(4,1):string())
    return "Client connect: "..parse_version(buf(5), tree)
  end,
  ["iD"] = function(buf, tree)
    return "Server version/ping: "..parse_version(buf, tree)
  end,

  ["MA"] = function(buf, tree)
    local str = buf:string()
    tree:add(proto, buf, "Sim setting:", str)
    return "Sim setting: " .. str
  end,

  -- Berth Requests
  ["BB"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Interpose berth"
  end,
  ["BC"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Cancel berth"
  end,

  -- Signals
  ["SA"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Set route"
  end,
  ["zD"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Cancel route"
  end,
  ["SB"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Apply isolation reminder to signal"
  end,
  ["SC"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Remove isolation reminder from signal"
  end,
  ["SD"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Apply general reminder to signal"
  end,
  ["SE"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Remove general reminder from signal"
  end,
  -- Auto buttons
  ["SF"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Set signal auto"
  end,
  ["SG"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Cancel signal auto"
  end,
  ["SH"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Apply isolation reminder to auto button"
  end,
  ["SI"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Apply general reminder to auto button"
  end,
  ["SJ"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Remove isolation reminder from auto button"
  end,
  ["SK"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Remove general reminder from auto button"
  end,
  -- Replacement buttons
  ["SP"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Cancel signal replacement"
  end,
  ["SQ"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Set signal replacement"
  end,
  ["SR"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Apply isolation reminder to replacement button"
  end,
  ["SS"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Apply general reminder to replacement button"
  end,
  ["ST"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Remove isolation reminder from replacement button"
  end,
  ["SU"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Remove general reminder from replacement button"
  end,

  -- Points Setting
  ["PB"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Key points normal"
  end,
  ["PC"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Key points reverse"
  end,
  ["PD"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Apply reminder to points"
  end,
  ["PE"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Remove reminder from points"
  end,

  -- Refresh State
  ["iB"] = function(buf, tree)
    tree:add(proto, buf, "Unknown message body content")
    return "Request refresh object state"
  end,

  -- Messages
  ["mA"] = function(buf, tree)
    tree:add(proto, buf(0, 2), "Simulation message type:", buf(0, 2):string())
    tree:add(proto, buf(2), "Message content:", buf(2):string())
    return "Simulation message"
  end,

  default = function(buf, tree, cmd)
    tree:add(proto, buf, "Unknown message body content")
    return "Unknown message ("..cmd..")"
  end,
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
  pinfo.cols.info = info
end

-- load the udp.port table
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(50505, proto)
tcp_table:add(50507, proto)
