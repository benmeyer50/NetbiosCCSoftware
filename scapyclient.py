from scapy.all import *

packetCount = 0
message = False
messageend = False
characterlist = []

def customAction(packet):
	global packetCount
	global message 
	global messageend
	global characterlist
	#print "Packet #" + str(packetCount) + ": " +packet[0][1].src + "==>" + packet[0][1].dst + ": " + str(packet[0].SUFFIX)
	suffixnum = packet[0].SUFFIX
	if(suffixnum == 23130):
		message = True
		#print message
		messageend = False
		#print messageend
		packetCount += 1
	elif(suffixnum == 23130 and packetCount > 1):
		messageend = True
		#print messageend
	elif(messageend == True and suffixnum == 23130):
		message = False
		packetCount = 0
		characterlist = characterlist[1:]
		print characterlist
		#print message
	asciivalue = hex(suffixnum)[4:]
	asciivalue = int(asciivalue, 16)
	character = chr(asciivalue)
	if(message == True):
		characterlist.append(character)
		packetCount += 1

sniff(filter="port 137", prn=customAction)
