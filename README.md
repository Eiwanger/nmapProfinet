# nmapProfinet
The script pn_discovery.nse discovers profinet devices in the local subnet and retrieves information about them.
It uses a profinet DCP (Discovery and Configuration Protocol) call with the ethernet multicast mac address and the service identify and parses the answer.

The second script is not finished yet. 
The use would be to send RPC/endpointmapper request to every device with port 34964 to know if there is a profinet device. Then proceed with implicit read request to get as much information about it as possible.

Update 2024
Official takeover and publishing by the DINA-Community in
https://github.com/DINA-community/ot-nmap-scritps

