local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local bin = require "bin"
local packet = require "packet"


description = [[ This script sends a 
	profinet dcp (discovery and configuration protocol) indetify all message
	as a multicast through the subnet and print the answers into a table]]

---
-- @usage
-- if the file is somewhere in the file system
-- nmap  --script <path>\pn_discovery
-- if the file is in nmap\scripts
-- nmap --script pn_discovery


-- @output
--	pn_discovery:
--|   devices:
--|
--|       ip_addr: 10.253.81.37
--|       mac_addr: 00:0E:8C:C9:41:15
--|       subnetmask: 255.255.255.0
--|       vendorId: 002A
--|       deviceId: 0105
--|       vendorvalue: S7-300
--|       deviceRole: 00
--|       nameOfStation: pn-io
--|
--|       ip_addr: 10.253.81.26
--|       mac_addr: AC:64:17:2C:C9:46
--|       subnetmask: 255.255.255.0
--|       vendorId: 002A
--|       deviceId: 0404
--|       vendorvalue: SIMATIC-HMI
--|       deviceRole: 00
--|_      nameOfStation: xd134xbvisu.profinetxaschnittstellexb103b2

-- @args
--
---

author = "Stefan Eiwanger"
 
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","info", "safe"}

prerule = function()
  if nmap.address_family() ~= 'inet' then
    stdnse.debug1("is IPv4 compatible only.")
    return false
  end

  return true
end

local pn_dcp_multicast = "01:0e:cf:00:00:00"


-- generate raw profinet identify all message
--@param iface interface table containing mac address
--@return eth_packet ethernet packet for sending over socket
build_eth_frame= function(iface)
	
	stdnse.debug(1, "Build packet for dcp identify all call.")
	stdnse.debug(1, "Interface: " .. iface.device)
	local pn_dcp_size = 46	-- min size of ethernet packet
	local eth_packet
	local src_mac = iface.mac
	

	local dest_mac = packet.mactobin(pn_dcp_multicast)
	local eth_proto = bin.pack("S", 0x9288)
	local blockData = bin.pack("SCCISSCC", 0xfefe, 0x05,0x00,0x10000010, 0x0400, 0x0400,0xff, 0xff)
	local padbyte = bin.pack("C", 0x00)


	
		
	-- build the packet
	eth_packet = dest_mac .. src_mac .. eth_proto .. blockData
	local length = string.len(eth_packet)
	
	-- fill the rest of the packet with 0x00 till ethernet min size is reached
	for  i = length, pn_dcp_size-1, 1 do

		eth_packet = eth_packet .. padbyte
	end
	return eth_packet
end



-- extract data from incoming dcp packets and store them into a table
--@param eth_data ethernet part of the recieved packet
--@param pn_data profinet part of the recieved packet == ethernet packetload
--@return device table with all extraced data from the pn_dcp
parse_pndcp = function(eth_data, pn_data)
	stdnse.debug(1, "Start parsing of answer")
	local pos = 7	-- start after the destination mac address (host)
	local deviceMacAddress
	local deviceRoleInterpretation = {} 
		deviceRoleInterpretation [0] = "PNIO Device"
		deviceRoleInterpretation [1] = "PNIO Controller"
		deviceRoleInterpretation [2] = "PNIO Multidevice"
		deviceRoleInterpretation [3] = "PNIO Supervisor"
	
	-- extract device mac address




	pos, deviceMacAddress = bin.unpack("HC",eth_data, pos)
	local tmp = deviceMacAddress

	for pos = 8, 12, 1 do
		_, deviceMacAddress = bin.unpack("HC",eth_data, pos)
		tmp = tmp.. ':' .. deviceMacAddress
	end
	deviceMacAddress = tmp
	
	stdnse.debug(1, "Device MAC address: %s", deviceMacAddress)

	-- check if the packet is a request
	local serviceType 
	_, serviceType= bin.unpack("C", pn_data, 4)
	stdnse.debug(1, "%x", serviceType)
	if (serviceType == 0) then return end 
	
	
	-- start extrating data from pn_dcp_response -- start with 1
	pos = 11
	local gesDCPDataLength = "" 
	_, gesDCPDataLength = bin.unpack("C", pn_data, pos)
	pos = pos +1
	_, tmp = bin.unpack("C", pn_data, pos)
	gesDCPDataLength = gesDCPDataLength + tmp
	--gesDCPDataLength = (gesDCPDataLength << 8) | tmp
	stdnse.debug(1,"DCP Datalength of full packet: %d", gesDCPDataLength)
	  
	-- extract data from DCP block
	local option, suboption
	local IP, deviceVendorValue, deviceRole, deviceId, nameofstation, dcpDatalength, subnetmask, standardGateway, vendorId = "", "", "", "", "", "", "", "", ""
	stdnse.debug(1, "Start extracting data from DCP block")
	while(pos < gesDCPDataLength) do

		pos = pos +1
		_,option = bin.unpack("C", pn_data, pos)
		pos = pos + 1
		_, suboption = bin.unpack("C", pn_data, pos)

		if option == 1 then -- IP
			if(suboption == 2) then
				pos = pos + 1				
				stdnse.debug(1, "Option IP, suboption IP")
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				stdnse.debug(1,"DCP Datalength of IP/IP %d", dcpDataLength)
				--dcpDataLength = (dcpDataLength << 8) | tmp
				
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				local endofIP = pos + 2 + 4
				
				stdnse.debug(1, "Position at start of IP address: %d", pos)
				for currentPos = pos + 3, endofIP, 1 do  -- get ip address
					_, tmp = bin.unpack("C",pn_data, currentPos)
					IP = IP .. "." .. tmp
				end
				pos = pos + 6 + 1
				
				IP = string.sub(IP,2)
				stdnse.debug(1, "IP address: %s", IP)
				stdnse.debug(1, "Position at end of IP address: %d", pos)
				--  subnetmask
				endofIP = endofIP + 4
					stdnse.debug(1, "Position at start of subnetmask: %d", pos)
				for currentPos = pos, endofIP, 1 do  -- get subnetmask
					_, tmp = bin.unpack("C",pn_data, currentPos)
					subnetmask = subnetmask .. "." .. tmp
				end
				pos = pos + 4
				
				subnetmask = string.sub(subnetmask,2)
				stdnse.debug(1, "Subnetmask: %s", subnetmask)
				stdnse.debug(1, "Position at end of subnetmask: %d", pos)
				
				--  standard gateway
				endofIP = endofIP + 4
				stdnse.debug(1, "Position at start of default gateway: %d", pos)
				for currentPos = pos, endofIP, 1 do  -- get standardgateway
					_, tmp = bin.unpack("C",pn_data, currentPos)
					standardGateway = standardGateway .. "." .. tmp
				end
				
				pos = endofIP
				
				
				standardGateway = string.sub(standardGateway,2)
				
				stdnse.debug(1, "Default gateway: %s", standardGateway)
				stdnse.debug(1, "Position at end of default gateway: %d", pos)
			
			
				
				
				stdnse.debug(1, "Position at end of IP: %d", pos)
				
				--[[if dcpDataLength%2 ~= 0 then
					pos = pos +1 -- add padding
				end
				--]]
			else
			stdnse.debug(1, "Option IP, suboption something else: %d", suboption)
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--dcpDataLength = (dcpDataLength << 8) | tmp
				stdnse.debug(1, "DCP datalength of IP/else: %d", dcpDataLength)
				pos = pos + dcpDataLength
				
				if dcpDataLength%2 ~= 0 then
					stdnse.debug(1, "dcpDatalength was odd, add padding +1 to pos")
					pos = pos +1 -- add padding
				end
				
			end
		elseif option == 2 then -- device properties
			if suboption == 1 then-- deviceVendorValue  manufacturer specific option
				stdnse.debug(1, "Option device properties, suboption manufacturer specific")
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--dcpDataLength = (dcpDataLength << 8) | tmp
				
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				
				local endOfVal = pos + dcpDataLength
				
				for pos = pos + 3, endOfVal, 1 do
					_, tmp = bin.unpack("C",pn_data, pos)
					
					deviceVendorValue = deviceVendorValue .. string.char(tmp)
				end
				
				pos = endOfVal
				if dcpDataLength%2 ~= 0 then
				stdnse.debug(1, "dcpDatalength was odd, add padding +1 to pos")
					pos = pos +1 -- add padding
				end

				

			elseif suboption == 2 then -- nameofstation
					-- get the length of the name
					stdnse.debug(1, "Option device properties, suboption name of station")
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--dcpDataLength = (dcpDataLength << 8) | tmp
				
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				local endOfVal = pos + dcpDataLength
				for pos = pos + 3, endOfVal, 1 do
					_, tmp = bin.unpack("C",pn_data, pos)
					nameofstation = nameofstation .. string.char(tmp)
				end
				
				pos = endOfVal
				if dcpDataLength%2 ~= 0 then
				stdnse.debug(1, "dcpDatalength was odd, add padding +1 to pos")
					pos = pos +1 -- add padding
				end
				

	
			
				
			elseif suboption == 3 then -- device id, vendor Id
				stdnse.debug(1, "Option device properties, suboption device ID")
				
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--dcpDataLength = (dcpDataLength << 8) | tmp
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				
				
				local endOfVal = pos + 2 + 2
				for pos = pos + 3, endOfVal, 1 do 
					_, tmp = bin.unpack("HC",pn_data, pos)
					vendorId = vendorId .. tmp
				end
				vendorId = "0x" .. vendorId
				
				pos = endOfVal +1
				endOfVal = endOfVal + 2
				
				for pos = pos, endOfVal, 1 do 
					_, tmp = bin.unpack("HC",pn_data, pos)
					deviceId = deviceId .. tmp
				end
				
				deviceId = "0x" .. deviceId
				
				pos = endOfVal


			elseif suboption == 4 then -- device role
				stdnse.debug(1, "Option device properties, suboption device role")
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--dcpDataLength = (dcpDataLength << 8) | tmp
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				
				pos = pos + 2 
				_,deviceRole = bin.unpack("C", pn_data, pos)
				pos = pos + 2 -- add 0x00 reserved block
				
				deviceRole = deviceRoleInterpretation[deviceRole] .. ' 0x0' .. deviceRole
				
			else
			stdnse.debug(1, "Option device properties, suboption something else: %d", suboption)
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				--dcpDataLength = (dcpDataLength << 8) | tmp
				dcpDataLength = dcpDataLength + tmp
				
				pos = pos + dcpDataLength
				if dcpDataLength%2 ~= 0 then
				stdnse.debug(2, "dcpDatalength was odd, add padding +1 to pos")
					pos = pos +1 -- add padding
				end
				
			end
		else  
			stdnse.debug(1, "Option something else: %d", option)
			pos = pos + 1
			_,dcpDataLength = bin.unpack("C", pn_data, pos)
			
			pos = pos +1
			_, tmp = bin.unpack("C", pn_data, pos)
			
			dcpDataLength = dcpDataLength + tmp
			--dcpDataLength = (dcpDataLength<<8) | tmp
			pos = pos + dcpDataLength
			if dcpDataLength%2 ~= 0 then
			stdnse.debug(1, "dcpDatalength was odd, add padding +1 to pos")
				pos = pos +1 -- add padding
			end
		
		end -- close if
		
	end -- close while
	
	-- store data into table
	local device = stdnse.output_table()
	device.ip_addr = IP
	device.mac_addr = deviceMacAddress
	device.subnetmask = subnetmask
	device.vendorId = vendorId
	device.deviceId = deviceId
	device.vendorvalue = deviceVendorValue
	device.deviceRole= deviceRole
	device.nameOfStation = nameofstation
	
	stdnse.debug(1, "End of parsing\n")
	
	return device
end

-- get all possible interfaces
--@param link  type of interface e.g. "ethernet"
--@param up status of the interface 
--@return result table with all interfaces which match the given requirements
getInterfaces = function(link, up)
  if( not(nmap.list_interfaces) ) then return end
  local interfaces, err = nmap.list_interfaces()
  local result = {}

  if ( not(err) ) then
    for _, iface in ipairs(interfaces) do
		if ( iface.link == link and
        iface.up == up and
        iface.mac ) then
			if #result == 0 then
				table.insert(result, iface)
			else 
			local exists = false
				for _, intface in ipairs(result) do
					if intface.mac == iface.mac then
						exists = true
					end
				end
				if not exists then
					table.insert(result, iface)
				end
			end	
		end
    end
  end
  return result
end

-- helpfunction for thread call
--@param iface interface table
--@param pn_dcp ethernet dcp packet to send 
--@param devices table for results
--@return devices, table with devices which answered to the dcp identify all call
discoverThread = function(iface, pn_dcp, devices)
	local condvar = nmap.condvar(devices)
	local dnet = nmap.new_dnet()
	local pcap_s = nmap.new_socket()
	pcap_s:set_timeout(2000)
	dnet:ethernet_open(iface.device)
	pcap_s:pcap_open(iface.device, 256, false, "ether proto 0x8892")
	
	local status, ethData, length, pn_data
	 
	dnet:ethernet_send(pn_dcp)	-- send the frame
	
	status = true
	while status do
		status, length, ethData, pn_data = pcap_s:pcap_receive()
	 
		if(status) then
			devices[#devices + 1] = parse_pndcp(ethData, pn_data)
		end
	end
	dnet:ethernet_close(iface.device);	-- close the sender

	

	pcap_s:close(iface.device)
condvar "signal"
return devices
end

-- main fuction
--@return 0 if no devices were found
--@return output_tab table for nmap to show the gathered information
action = function()
	local interface_e = nmap.get_interface()
	local interfaces = {}
	
	local output_tab = stdnse.output_table()
	output_tab.devices = {}
	
	-- check interface parameter

	local dnet = nmap.new_dnet()
	local pcap_s = nmap.new_socket()
	pcap_s:set_timeout(4000)
	
	 
	if(interface_e) then -- interface supplied with -e
		local iface = nmap.get_interface_info(interface_e)
		if not (iface and iface.link == 'ethernet') then
			stdnse.print_debug("%s not supported with %s", iface, SCRIPT_NAME)
			return false
		end		
		table.insert(interfaces, iface)
	else -- discover interfaces
		interfaces = getInterfaces("ethernet", "up")
	end
	
	-- check if at least one interface is available
	if #interfaces == 0 then
		print("No interfaces found")
		return false
	end
	
	-- get the frame we want to send
	
	
	local threads = {}

	local condvar = nmap.condvar(output_tab.devices)

	
	for _, iface in ipairs(interfaces) do
		local pn_dcp = build_eth_frame(iface) 
		--print(iface.device)
	
		local co = stdnse.new_thread(discoverThread, iface, pn_dcp, output_tab.devices)
		threads[co] = true
	end
	
	 -- wait for all threads to finish sniffing
  repeat
    for thread in pairs(threads) do
      if coroutine.status(thread) == "dead" then
        threads[thread] = nil
      end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil

	-- check the output if something is doubled there
	if #output_tab.devices == 0 then
		print("No profinet devices in the subnet")
		return 0
	end
	

	return output_tab
	
end	
