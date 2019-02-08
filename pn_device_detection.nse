local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local bin = require "bin"
local packet = require "packet"


description = [[This is the try to create a script for the idetification of profinet devices in a subnet ]]

---
-- @usage
--
-- @output
--
-- @args
--
---

author = "Stefan Eiwanger"
 
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","info"}


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
		print(iface)
		print(iface.link)
		if iface and iface.link == 'ethernet' then
		stdnse.print_debug("%s runs right", SCRIPT_NAME)
		return true
		end
	end
	
if(host.directly_connected) then 
stdnse.print_debug("host directly connected true")
end
stdnse.print_debug("host mac address src: \n")
stdnse.print_debug(host.mac_addr_src)
stdnse.print_debug("host interface:\n")
stdnse.print_debug(host.interface)
stdnse.print_debug("%s runs bad\n\n", SCRIPT_NAME)
	return false	


--return true
end

local pn_dcp_multicast = "01:0e:cf:00:00:00"


-- generate raw profinet identify all message
build_eth_frame= function(host)
	local pn_dcp_size = 46	-- min size of ethernet packet
	local eth_packet
	local src_mac = host.mac_addr_src
	local dest_mac = packet.mactobin(pn_dcp_multicast)
	local eth_proto = bin.pack("S", 0x9288)
	-- short FrameID, char ServiceId, char ServiceType,  int Xid, short ResponseDelay, short Dcp datalength, 
	-- char option, char suboption
	-- lsb! 
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

parse_pndcp = function(eth_data, pn_data)
	local pos = 7	-- start after the destination mac address (is mine)
	local deviceMacAddress
	 
	-- extract device mac address
	pos, deviceMacAddress = bin.unpack("HC",eth_data, pos)
	local tmp = deviceMacAddress

	for pos = 8, 12, 1 do
		_, deviceMacAddress = bin.unpack("HC",eth_data, pos)
		tmp = tmp.. ':' .. deviceMacAddress
	end
	deviceMacAddress = tmp
	print(deviceMacAddress)


	-- start extrating data from pn_dcp_response -- start with 1
	pos = 11
	local gesDCPDataLength = "" 
	_, gesDCPDataLength = bin.unpack("C", pn_data, pos)
	pos = pos +1
	_, tmp = bin.unpack("C", pn_data, pos)
	print("\n")
	gesDCPDataLength = gesDCPDataLength + tmp
	print("gesBlockLength: "..gesDCPDataLength)
	  
	-- extract data from DCP block

	local option, suboption
	local IP, deviceVendorValue, deviceRole, deviceId, nameofstation, dcpDatalength, subnetmask, standardGateway, vendorId = "", "", "", "", "", "", "", "", ""
	print("Pos: "..pos)
	while(pos < gesDCPDataLength) do

		pos = pos +1
		_,option = bin.unpack("C", pn_data, pos)
		pos = pos + 1
		_, suboption = bin.unpack("C", pn_data, pos)

	
		print("\noption: "..option)
		
		print("\nsuboption: "..suboption)
		--[[
		if option == 0x02 then 
		print("\nhex works")
		end
		if option == 2 then
			print("dec works")
		end
		if option == 02 then
			print("0 dec works\n")
		end
		--]]
		
		if option == 1 then -- IP
			if(suboption == 2) then
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				local endofIP = pos + 2 + 4
				
				for pos = pos + 2, endofIP, 1 do  -- get ip address
					_, tmp = bin.unpack("C",pn_data, pos)
					IP = IP .. "." .. tmp
				end
				pos = pos +endofIP
				--  subnetmask
				endofIP = endofIP + 4
				for pos = pos, endofIP, 1 do  -- get subnetmask
					_, tmp = bin.unpack("C",pn_data, pos)
					subnetmask = subnetmask .. "." .. tmp
				end
				pos = pos +endofIP
				--  standard gateway
					endofIP = endofIP + 4
				for pos = pos, endofIP, 1 do  -- get standardgateway
					_, tmp = bin.unpack("C",pn_data, pos)
					standardGateway = standardGateway .. "." .. tmp
				end
				pos = pos +endofIP
				
				IP = string.sub(IP,2)
				--subnetmask = string.sub(subnetmask,2)
				--standardGateway = string.sub(standardGateway,2)
				-- todo find error in gateway and subnetmask
				if dcpDataLength%2 ~= 0 then
					pos = pos +1 -- add padding
				end
				print("IP:" ,IP)
				print("subnetmask:", subnetmask)
				print("gateway:", standardGateway)
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
				print("pos: ", pos)
				print("size:" ,size)
				for pos = pos + 3, size, 1 do
					_, tmp = bin.unpack("C",pn_data, pos)
					print("dvendor value: ", string.char(tmp))
					deviceVendorValue = deviceVendorValue .. string.char(tmp)
				end
				--print("pos before add size", pos)
				pos = size
				if dcpDataLength%2 ~= 0 then
					pos = pos +1 -- add padding
				end
				
				print("\ndeviceVendorValue: ", deviceVendorValue)
				print("pos: ", pos)
				

			elseif suboption == 2 then -- nameofstation
					-- get the length of the name
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				local size = pos + dcpDataLength
				for pos = pos + 2, size, 1 do
					_, tmp = bin.unpack("C",pn_data, pos)
					nameofstation = nameofstation .. string.char(tmp)
				end
				
				if dcpDataLength%2 ~= 0 then
					pos = pos +1 -- add padding
				end
				pos = size
				print("\nNameofStation:", nameofstation)
			
			
				
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
				print("\nvendorId:")
				print(vendorId)
				print("\ndeviceId:")
				print(deviceId)

			elseif suboption == 4 then -- device role
				pos = pos + 1
				_,dcpDataLength = bin.unpack("C", pn_data, pos)
				pos = pos +1
				_, tmp = bin.unpack("C", pn_data, pos)
				dcpDataLength = dcpDataLength + tmp
				--pos = pos + 2 -- first 2 byte are blockinfo therefore not important
				
				pos = pos + 2 
				_,deviceRole = bin.unpack("HC", pn_data, pos)
				pos = pos + 2 -- add 0x00 reserved block
				
				print("\nDeviceRole:")
				print(deviceRole)
			else
				print("\nelse device now\n")
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
			print("\nelse option now\n")
			pos = pos + 1
			_,dcpDataLength = bin.unpack("C", pn_data, pos)
			
			pos = pos +1
			_, tmp = bin.unpack("C", pn_data, pos)
			
			dcpDataLength = dcpDataLength + tmp
			print("dcpDataLength: ",dcpDataLength)
			pos = pos + dcpDataLength
			if dcpDataLength%2 ~= 0 then
				pos = pos +1 -- add padding
			end
		
		end -- close if
		
	end -- close while
	return true

--return true, dataTable	
end

	

action = function(host)
 local dnet = nmap.new_dnet()
 local pcap_s = nmap.new_socket()
 pcap_s:set_timeout(4000)
 local timeout = 5000
 stdnse.print_debug("\n%s starts now\n", SCRIPT_NAME)
 print(host.interface)
 
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
 print ("yes\n")
 
parse_pndcp(ethData, pn_data)
 
 else
 print ("no\n")
 end
 end
 --[[
 if(status) then

	parse_pndcp(ethData)
 end
 --]]


 dnet:ethernet_close();	-- close the sender

 
 --[[
 local status, ethData, pnData
 status, _, ethdata, pnData = pcap:pcap_receive()  
 -- returns boolean successfull or not, packet length, 
 --data from 2 and 3 osilayer, packet capture time
 
 if status then
	-- functioncall for parsing data
	status,  = parse_pndcp(ethData)
	--]]
	
	pcap_s:close()
	 stdnse.print_debug("\n%s ends now\n",SCRIPT_NAME)
	
	 
	 
end	
