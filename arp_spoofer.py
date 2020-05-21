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


packet = scapy.ARP(op = 2, pdst = "10.0.2.8", hwdst = "08:00:27:e6:e5:59", psrc = "10.0.2.1")
print(packet.show())
print(packet.summary())
