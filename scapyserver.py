from scapy.all import *

text = raw_input('Message:')
characterlist = list(text)
for character in characterlist[:]:
	asciivalue = ord(character) 
	suffixnum = 16705+asciivalue
	a = IP(src = '1.1.1.1', dst = '192.168.235.255')/UDP(sport = 8, dport = 137)/NBNSQueryRequest(SUFFIX = suffixnum)
	send(a)
