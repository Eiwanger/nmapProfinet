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
--[[
if host.directly_connected == true and
	host.mac_addr ~= nil and
	host.mac_addr_src ~= nil and
	host.interface ~= nil then
		local iface = nmap.get_interface_info(host.interface)
		if iface and iface.link == 'ethernet' then
		stdnse.print_debug("%s runs right", SCRIPT_NAME)
		return true
		end
	end
stdnse.print_debug(host.directly_connected)
stdnse.print_debug(host.mac_addr)
stdnse.print_debug(host.mac_addr_src)

stdnse.print_debug(host.interface)
stdnse.print_debug("%s runs bad\n\n", SCRIPT_NAME)
	return false	
--]]

return true
end

pn_dcp_size = 46	-- min size of ethernet packet
pn_dcp_multicast = "01:0E:CF:00:00:00" -- dcp multicast address

-- generate raw profinet identify all message
build_eth_frame= function(host)
	local packet = packet.Frame:new()
	
	local src_mac = host.mac_addr_src
	local dest_mac = packet.mactobin(pn_dcp_multicast)
	local eth_proto = bin.pack("S", 0x8892)
	local blockData = bin.pack("SCCISCC", 0xfefe, 0x05,0x00,0x01000001, 0x0004, 0xff, 0xff)
	
	packet = Frame:build_ether_frame(dest_mac, src_mac, eth_proto, blockData)
	return packet
end

parse_pndcp = function(ethData)
local pos = 14
local data
pos, data = bin.unpack("", ethData, pos)
if  data ~= 0xfeff then
	return false, _  -- return if the packet is not a response
end



return true, dataTable	
end
	
	

action = function(host)
 local dnet = nmap.new_dnet()
 local pcap_s = nmap.new_socket()

 stdnse.print_debug("\n%s starts now\n", SCRIPT_NAME)
 print(host.interface)
 
--dnet:ethernet_open(host.interface)
 dnet:ethernet_open("wlp3s0")
 pcap_s.pcap_open(host.interface, 256, false, "ether proto 0x8892")

 
 local pn_dcp = build_eth_frame(host) -- get the frame we want to send
 try(dnet:ethernet_send(pn_dcp))	-- send the frame
 dnet:ethernet_close();	-- close the sender
 stdnse.print_debug("\n%s ends now\n",SCRIPT_NAME)
 --[[
 local status, ethData, pnData
 status, _, ethdata, pnData = pcap:pcap_receive()  
 -- returns boolean successfull or not, packet length, 
 --data from 2 and 3 osilayer, packet capture time
 
 if status then
	-- functioncall for parsing data
	status,  = parse_pndcp(ethData)
	--]]
end	
	
	
	
	
 
 
 
 
 
 
	
