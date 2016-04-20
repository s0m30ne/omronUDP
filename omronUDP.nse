local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
识别欧姆龙PLC Fins协议控制器信息，该协议开放在9600端口
]]

---
-- @usage
-- nmap -sU -p 9600 --script=omron-info <target>
-- @output
--9600/udp open  OMRON FINS
--| omronudp-info: 
--|   Controller Model: CJ2M-CPU31          02.00
--|   Controller Version: 02.00
--|   For System Use: 
--|   Program Area Size: 10
--|   IOM size: 23
--|   No. DM Words: 32768
--|   Timer/Counter: 8
--|   Expansion DM Size: 1
--|   No. of steps/transitions: 0
--|   Kind of Memory Card: No Memory Card
--|   Memory Card Size: 0

author = "s0m30ne"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

portrule = shortport.portnumber(9600, "udp")

action = function(host,port)

  local socket = nmap.new_socket()
  local try = nmap.new_try(function() socket:close() end)
  local controller_data_read = bin.pack("H", "80000200000000230000050100")
  local output = stdnse.output_table()
  local memcard = {[0] = "No Memory Card", [1] = "SPRAM", [2] = "EPROM", [3] = "EEPROM"}

  try(socket:connect(host, port))
  try(socket:send(controller_data_read))
  local status, response = socket:receive()

  if status then
    local pos, header = bin.unpack("C", response, 1)
    if(header == 0xc0 or header == 0xc1) then
      local pos, Controller_Model = bin.unpack("z", response,15)
      local pos, Controller_Version = bin.unpack("z", response, 35)
      local pos, System_Use = bin.unpack("z", response, 55)
      local pos, Area_Size = bin.unpack(">S", response, 95)
      local pos, IOM_Size = bin.unpack("C", response, pos)
      local pos, DM_Words = bin.unpack(">S", response, pos)
      local pos, timer = bin.unpack("C", response, pos)
      local pos, DM_Size = bin.unpack("C", response, pos)
      local pos, steps = bin.unpack(">S", response, pos)
      local pos, mem_card_type = bin.unpack("C", response, pos)
      local pos, Card_Size = bin.unpack(">S", response, pos)

      output["Controller Model"] = Controller_Model
      output["Controller Version"] = Controller_Version
      output["For System Use"] = System_Use
      output["Program Area Size"] = Area_Size
      output["IOM size"] = IOM_Size
      output["No. DM Words"] = DM_Words
      output["Timer/Counter"] = timer
      output["Expansion DM Size"] = DM_Size
      output["No. of steps/transitions"] = steps
      output["Kind of Memory Card"] = memcard[mem_card_type]
      output["Memory Card Size"] = Card_Size
      
      socket:close()
      return output
    else
      socket:close()
      return nil
    end
  else
    socket:close()
    return false
  end
end