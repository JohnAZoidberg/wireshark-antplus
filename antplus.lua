ant_plus_protocol = Proto("Antplus",  "ANT+ Protocol")

local sync          = ProtoField.uint8  ("ant.sync",     "Sync",     base.HEX)
local msg_len       = ProtoField.uint8  ("ant.msg_len",  "Length",   base.DEC)
local msg_id        = ProtoField.uint8  ("ant.msg_id",   "ID",       base.HEX)
local msg_content   = ProtoField.bytes  ("ant.content",  "Content",  base.NONE)
local checksum      = ProtoField.uint8  ("ant.checksum", "Checksum", base.HEX)

local msg_name      = ProtoField.string ("ant.msg_name", "Message Name")

local startup_notify_types = {
  [0x00] = "Hardware Reset",
  [0x01] = "Watchdog Reset",
  [0x10] = "Command Reset",
  [0x20] = "Synchronous Reset",
  [0x40] = "Suspend Reset",
}
local startup_notif = ProtoField.uint8  ("ant.startup_notif", "Startup Notification", base.DEC, startup_notify_types)

local ant_version   = ProtoField.string ("ant.version.str", "ANT Version", base.ASCII)
local serial_number = ProtoField.uint32 ("ant.serial_number.int", "Serial Number", base.DEC)
local channel_num   = ProtoField.uint8  ("ant.channel_num", "Channel Number", base.DEC)
local channel_types	= {
  [0x00] = "Bidi Slave/Receive Channel",
  [0x01] = "Bidi Master/Transmit Channel",
  [0x02] = "Shared Bidi Slave/Receive",
  [0x04] = "Shared Bidi Master/Transmit",
  [0x08] = "Slave/Receive Only (diagnostic)",
  [0x10] = "Master/Transmit Only (legacy)",
}
local channel_type  = ProtoField.uint8  ("ant.channel_status.channel_type", "Channel Type", base.DEC, channel_type, 0xF0)
local network_num   = ProtoField.uint8  ("ant.channel_status.network_num", "Network Number", base.DEC)
local channel_states = {
  [0x00] = "Un-Assigned",
  [0x01] = "Assigned",
  [0x02] = "Searching",
  [0x04] = "Tracking"
}
local channel_state = ProtoField.uint8  ("ant.channel_status.channel_state", "Channel State",  base.DEC, channel_states, 0x03)

local resp_msg_id   = ProtoField.uint8  ("ant.resp_msg_id",    "Responding to Message ID",     base.HEX)
local msg_code      = ProtoField.uint8  ("ant.msg_code",       "Message/Response Code",        base.HEX)

local broadcast_data= ProtoField.bytes  ("ant.broadcast_data", "Broadcast Data",               base.NONE)
-- TODO: Decode
local flag_byte     = ProtoField.uint8  ("ant.flag_byte",      "Flag Byte",                    base.HEX)

local req_msg_id    = ProtoField.uint8  ("ant.req_msg_id",     "Requesting Message with ID",   base.HEX)

local max_channels  = ProtoField.uint8  ("ant.max_channels",   "Number of available channels", base.DEC)
local max_networks  = ProtoField.uint8  ("ant.max_networks",   "Number of available networks", base.DEC)
-- TODO: Decode
local standard_opts = ProtoField.uint8  ("ant.max_networks",   "Standard Options",             base.HEX)
local advanced_1    = ProtoField.uint8  ("ant.advanced_1",     "Advanced Options 1",           base.HEX)
local advanced_2    = ProtoField.uint8  ("ant.advanced_2",     "Advanced Options 2",           base.HEX)
local max_srcore    = ProtoField.uint8  ("ant.maxsrcore",      "Max sensRCore channels",       base.DEC)
local advanced_3    = ProtoField.uint8  ("ant.advanced_3",     "Advanced Options 3",           base.HEX)
local advanced_4    = ProtoField.uint8  ("ant.advanced_4",     "Advanced Options 4",           base.HEX)

local device_num    = ProtoField.uint8  ("ant.device_num",     "Device Number",                base.HEX)
-- TODO: Decode
-- 0x78 is HRM
local dev_type_id   = ProtoField.uint8  ("ant.dev_type_id",    "Device Type ID",               base.HEX)
local tx_type       = ProtoField.uint8  ("ant.tx_type",        "Transmission Type",            base.HEX)

local filler        = ProtoField.uint8  ("ant.filler", "Filler", base.HEX)

local extended_assign_states = {
  [0x00] = "None",
  [0x01] = "Background Scanning Enable",
  [0x04] = "Frequency Agility Enable",
  [0x10] = "Fast Channel Initialization Enable",
  [0x20] = "Asynchronous Transmission Enable"
}
local extended_assign = ProtoField.uint8  ("ant.assign_channel.extended_assign", "Extended Assign",  base.DEC, extended_assign_states)
local msg_period    = ProtoField.uint8  ("ant.msg_period.period", "Channel Messaging Period",  base.DEC)

ant_plus_protocol.fields = {
  sync, msg_len, msg_id, msg_content, checksum,
  -- Ant Version Message
  ant_version,
  -- Serial Number Message
  serial_number,
  -- Channel Status Message
  channel_num,
  channel_type,
  network_num,
  channel_state,
  -- Channel Event Or Response Message
  resp_msg_id,
  msg_code,
  -- Startup Notification Message
  startup_notif,
  -- Boardcast Data Message
  broadcast_data,
  flag_byte,
  -- Request Message
  req_msg_id,
  -- Capabilities Response Message
  max_channels,
  max_networks,
  standard_opts,
  advanced_1,
  advanced_2,
  max_srcore,
  advanced_3,
  advanced_4,
  -- Channel ID Message
  device_num,
  dev_type_id,
  tx_type,
  -- Generic
  filler,
  -- Assign Channel Message
  extended_assign,
  -- Channel Messaging Period Message
  msg_period,
}

local invalid_checksum = ProtoExpert.new("ant.invalid_checksum_expert", "Invalid checksum",
                                     expert.group.MALFORMED, expert.severity.WARN)
ant_plus_protocol.experts = { invalid_checksum }

local msg_id_field       = Field.new("ant.msg_id")
local msg_content_field  = Field.new("ant.content")

-- XOR all bytes
function calc_checksum(buffer)
  local bytes = buffer:bytes()
  local checksum = bytes:get_index(0)
  for i=1,bytes:len()-1 do
    checksum = bit.bxor(checksum, bytes:get_index(i))
  end
  return checksum
end

function ant_plus_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = ant_plus_protocol.name

  local subtree = tree:add(ant_plus_protocol, buffer(), "ANT Protocol Data")
  local messageSubtree = subtree:add(ant_plus_protocol, buffer(), "Message")

  subtree:add_le(sync,        buffer(0, 1))
  subtree:add_le(msg_len,     buffer(1, 1))
  subtree:add_le(msg_id,      buffer(2, 1))
  -- TODO: Check that msg_len == length - 4
  local content_buffer = buffer(3, length - 4) -- TODO: I'm sure there's a way to avoid this extra variable
  subtree:add(msg_content, content_buffer) -- 4 is the number of other fields
  subtree:add_le(checksum,    buffer(length - 1,1))


  -- TODO: Get checksum from variable
  -- Analyze -> Show Expert Info
  if buffer(length - 1, 1):uint() ~= calc_checksum(buffer(0, length - 1)) then
    subtree:add_proto_expert_info(invalid_checksum)
  end

  id = msg_id_field()()
  content = msg_content_field()()
  -- TODO: Parse outgoing messages to device
  if id == 0x42 then
    messageSubtree:add(msg_name, "Assign Channel Message")
    messageSubtree:add(channel_num, content_buffer(0, 1))
    messageSubtree:add(channel_type, content_buffer(1, 1))
    messageSubtree:add(network_num, content_buffer(2, 1))
    messageSubtree:add(extended_assign, content_buffer(3, 1))
  elseif id == 0x43 then
    messageSubtree:add(msg_name, "Channel Messaging Period Message")
    messageSubtree:add(channel_num, content_buffer(0, 1))
    -- TODO: Is there a better way to modify the data?
    local raw_period = content_buffer(1, 2):le_uint()
    local period = 32768 / raw_period
    local text = "Messaging Period: ".. raw_period .. " (" .. string.format("%.3f", period) .. " Hz)"
    messageSubtree:add(msg_period, content_buffer(1, 2)):set_text(text)
  elseif id == 0x44 then
    messageSubtree:add(msg_name, "Channel Search Timeout Message")
  elseif id == 0x45 then
    messageSubtree:add(msg_name, "Channel RF Frequency Message")
  elseif id == 0x46 then
    messageSubtree:add(msg_name, "Set Network Key Message")
  elseif id == 0x4a then
    messageSubtree:add(msg_name, "Reset System Message")
    messageSubtree:add(filler, content_buffer(0, 1))
  elseif id == 0x4b then
    messageSubtree:add(msg_name, "Open Channel Message")
    messageSubtree:add(channel_num, content_buffer(0, 1))
  elseif id == 0x4c then
    messageSubtree:add(msg_name, "Close Channel Message")
    messageSubtree:add(channel_num, content_buffer(0, 1))
  elseif id == 0x4d then
    messageSubtree:add(msg_name, "Request Message")
    messageSubtree:add(channel_num, content_buffer(0, 1))
    messageSubtree:add(req_msg_id, content_buffer(1, 1))
  elseif id == 0x51 then
    messageSubtree:add(msg_name, "Channel ID Message")
    messageSubtree:add(channel_num, content_buffer(0, 1))
    messageSubtree:add(device_num, content_buffer(1, 2))
    messageSubtree:add(dev_type_id, content_buffer(3, 1))
    messageSubtree:add(tx_type, content_buffer(4, 1))
  elseif id == 0x63 then
    messageSubtree:add(msg_name, "Low Priority Search Timeout Message")
  elseif id == 0x66 then
    messageSubtree:add(msg_name, "Enable Ext RX Message")
  elseif id == 0x6f then
    messageSubtree:add(msg_name, "StartupNotificationMessage")
    messageSubtree:add(startup_notif, content_buffer(0, 1))
  elseif id == 0x54 then
    messageSubtree:add(msg_name, buffer(), "CapabilitiesResponseMessage")
    messageSubtree:add(max_channels, content_buffer(0, 1))
    messageSubtree:add(max_networks, content_buffer(1, 1))
    messageSubtree:add(standard_opts, content_buffer(2, 1))
    messageSubtree:add(advanced_1, content_buffer(3, 1))
    messageSubtree:add(advanced_2, content_buffer(4, 1))
    messageSubtree:add(max_srcore, content_buffer(5, 1))
    -- Optional
    if content_buffer:len() > 6 then
      messageSubtree:add(advanced_3, content_buffer(6, 1))
    end
    if content_buffer:len() > 7 then
      messageSubtree:add(advanced_4, content_buffer(7, 1))
    end
    -- TODO:
    -- standard options
    -- - no receive channels
    -- - no transmit channels
    -- - no receive msgs
    -- - no transmit msgs
    -- - no ackd msgs
    -- - no burst msgs
    -- advanced
    -- advanced 2
    -- max sensRcore channels
    -- advanced 3
    -- advanced 4
  elseif id == 0x3e then
    messageSubtree:add(msg_name, buffer(), "AntVersionMessage")
    messageSubtree:add(ant_version, content_buffer)
  elseif id == 0x61 then
    messageSubtree:add(msg_name, "SerialNumberMessage")
    -- The serial number is a 4-byte, little-endian encoded unsigned integer.
    messageSubtree:add_le(serial_number, content_buffer)
  elseif id == 0x52 then
    messageSubtree:add(msg_name, "ChannelStatusMessage")
    messageSubtree:add(channel_num, content_buffer(0, 1))
    channel_status = content_buffer(1, 1)
    messageSubtree:add(channel_type, channel_status)
    messageSubtree:add(network_num, bit.band(channel_status:uint(), 0x0C)) -- TODO: This doesn't show the correlation to the hex dump
    messageSubtree:add(channel_state, channel_status)
  elseif id == 0x40 then
    messageSubtree:add(msg_name, buffer(), "ChannelEventOrResponseMessage")
    messageSubtree:add(channel_num, content_buffer(0, 1))
    messageSubtree:add(resp_msg_id, content_buffer(1, 1))
    -- TODO: if resp_msg_id == 1 then ChannelEvent, else response
    messageSubtree:add(msg_code, content_buffer(2, 1))
    -- TODO: Might include extra events
  elseif id == 0x4e then
    messageSubtree:add(msg_name, buffer(), "BroadcastDataMessage")
    messageSubtree:add(channel_num, content_buffer(0, 1))
    messageSubtree:add(broadcast_data, content_buffer(1, 8))

    -- TODO: Decode data
    -- This is only possible by knowing the channel/device type
    -- Must use stateful detection based on previous Channel ID Message

    -- Optional
    if content_buffer:len() > 9 then
      messageSubtree:add(flag_byte, content_buffer(9, 1))
      -- TODO: Decode flag byte and find out the length
      -- messageSubtree:add(extended_data, content_buffer(10, x))
    end
  else
    messageSubtree:add(msg_name, buffer(), "UnknownMessage")
  end
end

-- > View -> Internal -> Dissector table
DissectorTable.get("usb.bulk"):add(0xffff, ant_plus_protocol)
