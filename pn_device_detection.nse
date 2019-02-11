local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local bin = require "bin"
local packet = require "packet"


description = [[ This script checks if it is called in a ethernet subnet and if so, sends a 
	profinet dcp (discovery and configuration protocol) indetify all message
	as a multicast through the subnet and print the answers into a table]]

---
-- @usage
--	nmap -- script pn_discovery

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


hostrule = function(host)
	stdnse.print_debug("\n\n%s starts", SCRIPT_NAME)
	if nmap.address_family() ~= 'inet' then
		stdnse.print_debug("%s is IPv4 compatible only.", SCRIPT_NAME)
	return false
	end

	if host.directly_connected == true and
		host.mac_addr_src ~= nil and
		host.interface ~= nil then
		
		local iface = nmap.get_interface_info(host.interface)
		if iface and iface.link == 'ethernet' then
			return true
		end		
	end
	stdnse.print_debug("\n%s: Make sure targethost is in the local ethernet.\n", SCRIPT_NAME)

	return false	
end

local pn_dcp_multicast = "01:0e:cf:00:00:00"


-- generate raw profinet identify all message
build_eth_frame= function(host)
	local pn_dcp_size = 46	-- min size of ethernet packet
	local eth_packet
	local src_mac = host.mac_addr_src
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
parse_pndcp = function(eth_data, pn_data)
	local pos = 7	-- start after the destination mac address (is mine)
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



	-- start extrating data from pn_dcp_response -- start with 1
	pos = 11
	local gesDCPDataLength = "" 
	_, gesDCPDataLength = bin.unpack("C", pn_data, pos)
	pos = pos +1
	_, tmp = bin.unpack("C", pn_data, pos)
	gesDCPDataLength = gesDCPDataLength + tmp

	  
	-- extract data from DCP block
	local option, suboption
	local IP, deviceVendorValue, deviceRole, deviceId, nameofstation, dcpDatalength, subnetmask, standardGateway, vendorId = "", "", "", "", "", "", "", "", ""

	while(pos < gesDCPDataLength) do

		pos = pos +1
		_,option = bin.unpack("C", pn_data, pos)
		pos = pos + 1
		_, suboption = bin.unpack("C", pn_data, pos)

		if option == 1 then -- IP
			if(suboption == 2) then
				pos = pos + 1				
				
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				local endofIP = pos + 2 + 4
				
				for pos = pos + 3, endofIP, 1 do  -- get ip address
					_, tmp = bin.unpack("C",pn_data, pos)
					IP = IP .. "." .. tmp
				end
				pos = pos + 6+ 1
				--  subnetmask
				endofIP = endofIP + 4
				for pos = pos, endofIP, 1 do  -- get subnetmask
					_, tmp = bin.unpack("C",pn_data, pos)
					subnetmask = subnetmask .. "." .. tmp
				end
				pos = pos + 4
				--  standard gateway
					endofIP = endofIP + 4
				for pos = pos, endofIP, 1 do  -- get standardgateway
					_, tmp = bin.unpack("C",pn_data, pos)
					standardGateway = standardGateway .. "." .. tmp
				end
				pos = pos + 4
				
				IP = string.sub(IP,2)
				subnetmask = string.sub(subnetmask,2)
				standardGateway = string.sub(standardGateway,2)
				
				
				if dcpDataLength%2 ~= 0 then
					pos = pos +1 -- add padding
				end

			end
		elseif option == 2 then -- device properties
			if suboption == 1 then-- deviceVendorValue  manufacturer specific option
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				local size = pos + dcpDataLength
				
				for pos = pos + 3, size, 1 do
					_, tmp = bin.unpack("C",pn_data, pos)
					
					deviceVendorValue = deviceVendorValue .. string.char(tmp)
				end
				
				pos = size
				if dcpDataLength%2 ~= 0 then
					pos = pos +1 -- add padding
				end

				

			elseif suboption == 2 then -- nameofstation
					-- get the length of the name
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				local size = pos + dcpDataLength
				for pos = pos + 3, size, 1 do
					_, tmp = bin.unpack("C",pn_data, pos)
					nameofstation = nameofstation .. string.char(tmp)
				end
				
				pos = size
				if dcpDataLength%2 ~= 0 then
					pos = pos +1 -- add padding
				end
				

			
			
				
			elseif suboption == 3 then -- device id, vendor Id
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				
				
				local size = pos + 2 + 2
				for pos = pos + 3, size, 1 do 
					_, tmp = bin.unpack("HC",pn_data, pos)
					vendorId = vendorId .. tmp
				end
				
				pos = size +1
				size = size + 2
				
				for pos = pos, size, 1 do 
					_, tmp = bin.unpack("HC",pn_data, pos)
					deviceId = deviceId .. tmp
				end
				pos = size


			elseif suboption == 4 then -- device role
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				
				pos = pos + 2 
				_,deviceRole = bin.unpack("C", pn_data, pos)
				pos = pos + 2 -- add 0x00 reserved block
				
				deviceRole = deviceRoleInterpretation[deviceRole] .. ' 0x0' .. deviceRole

			else
			
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				
				pos = pos + dcpDataLength
				if dcpDataLength%2 ~= 0 then
					pos = pos +1 -- add padding
				end
				
			end
		else  
			pos = pos + 1
			_,dcpDataLength = bin.unpack("C", pn_data, pos)
			
			pos = pos +1
			_, tmp = bin.unpack("C", pn_data, pos)
			
			dcpDataLength = dcpDataLength + tmp
			
			pos = pos + dcpDataLength
			if dcpDataLength%2 ~= 0 then
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
	--local IP, deviceVendorValue, deviceRole, deviceId, nameofstation, dcpDatalength, subnetmask, standardGateway, vendorId
	return device
end

	

action = function(host)
	local dnet = nmap.new_dnet()
	local pcap_s = nmap.new_socket()
	local output_tab = stdnse.output_table()
	output_tab.devices = {}
	pcap_s:set_timeout(4000)
	--stdnse.print_debug("\n%s starts now\n", SCRIPT_NAME)
	-- print(host.interface)
	 
	dnet:ethernet_open(host.interface)
	 --dnet:ethernet_open("wlp3s0")
	 
	local pn_dcp = build_eth_frame(host) -- get the frame we want to send

	pcap_s:pcap_open(host.interface, 256, false, "ether proto 0x8892")
	local status, ethData, length, pn_data
	 
	dnet:ethernet_send(pn_dcp)	-- send the frame
	 
	status, length, ethData, pn_data = pcap_s:pcap_receive()  -- first is my call
	while status do
		status, length, ethData, pn_data = pcap_s:pcap_receive()
	 
		if(status) then
			output_tab.devices[#output_tab.devices + 1] = parse_pndcp(ethData, pn_data)
		end
	end
	dnet:ethernet_close();	-- close the sender

	

	pcap_s:close()
	return output_tab
end	
