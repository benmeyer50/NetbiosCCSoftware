from scapy.all import *

text = raw_input('Message:')
characterlist = list(text.upper())
characterstring = ""
index = 0

a = IP(src = '1.1.1.1', dst = '192.168.235.255')/UDP(sport = 8, dport = 137)/NBNSQueryRequest(SUFFIX = 23130)
send(a)


while (index < len(characterlist)):
	character1 = hex(ord("Z"))[2:]+hex(ord(characterlist[index]))[2:]
	characterstring = '0x'+character1
	suffixnum = int(characterstring,16)
	print suffixnum
	index += 1
	a = IP(src = '1.1.1.1', dst = '192.168.235.255')/UDP(sport = 8, dport = 137)/NBNSQueryRequest(SUFFIX = suffixnum)
	send(a)

character1 = hex(ord("Z"))[2:]+hex(ord("Z"))[2:]
characterstring = '0x'+character1
suffixnum = int(characterstring,16)
print suffixnum
index += 1
a = IP(src = '1.1.1.1', dst = '192.168.235.255')/UDP(sport = 8, dport = 137)/NBNSQueryRequest(SUFFIX = suffixnum)
send(a)
send(a)
