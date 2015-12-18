from scapy.all import *

packetCount = 0
message = False
messageend = False
def customAction(packet):
	global packetCount
	global message 
	global messageend
	packetCount += 1
	print "Packet #" + str(packetCount) + ": " +packet[0][1].src + "==>" + packet[0][1].dst + ": " + str(packet[0].SUFFIX)
	suffixnum = packet[0].SUFFIX
	if(suffixnum == 23130):
		message = True
		print message
		messageend = False
		print messageend
	if(suffixnum == 23130):
		messageend = True
		print messageend
	if(messageend == True and suffixnum == 23130):
		message = False
		print message
	asciivalue = hex(suffixnum)[4:]
	asciivalue = int(asciivalue, 16)
	character = chr(asciivalue)
	if(message == True):
		return "! " + character + " !"

sniff(filter="port 137", prn=customAction)
