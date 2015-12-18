from scapy.all import *

packetCount = 0

def customAction(packet):
	global packetCount
	packetCount += 1
	print "Packet #" + str(packetCount) + ": " +packet[0][1].src + "==>" + packet[0][1].dst + ": " + str(packet[0].SUFFIX)
	suffixnum = packet[0].SUFFIX
	asciivalue = suffixnum-90
	character = chr(asciivalue)
	return "! " + character + " !"


sniff(filter="port 137", prn=customAction)
