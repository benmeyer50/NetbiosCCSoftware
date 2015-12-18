from scapy.all import *

packetCount = 0
message = False
messageend = False

def customAction(packet):
	global packetCount
	packetCount += 1
	print "Packet #" + str(packetCount) + ": " +packet[0][1].src + "==>" + packet[0][1].dst + ": " + str(packet[0].SUFFIX)
	suffixnum = packet[0].SUFFIX
	if(suffixnum == 23130):
		message = True
	if(suffixnum == 23130):
		messageend = True
	if(messageend1 and suffixnum == 23130):
		message = False
	asciivalue = hex(suffixnum)[4:]
	asciivalue = int(asciivalue, 16)
	character = chr(asciivalue)
	if(message):
		return "! " + character + " !"

sniff(filter="port 137", prn=customAction)
