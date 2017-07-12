#!/usr/bin/env python
# encoding: utf-8
"""
    pbkdf2
    ~~~~~~
    PBKDF2 implementation for Python.
    UWB Division of Computing and Software Systems  
    CSS 337 Secure Systems -- Winter 2016
    Mariana Chagoyan 
    Encryption Tool--Encryption Key(Ke) && HMAC key(Kh)
    
    Description:
    Creates an Encryptionkey(ke) and HMACkey(kh) from Masterkey(Km)
    using a Hash Message Authentication Code(HMAC) function
    It uses the following:
    Two different strings or other different input as the salt argument. 
    Use a sha-512 HMAC, and use the first 256 bits as your keys.
    Part A:2.1	Implementation using different inputs as salt arguments
    This implementation uses 2 files (included in folder):
    a)	sha-512-HMAC-test2a.py
    b)	pbkdf2-test1.py

"""

import hashlib
import hmac

MASTER_KEY= "?)?t?c8T? 6?=D?"
KEY_BYTES=MASTER_KEY.encode('ascii')
MESSAGE = "uDRRRmAUtbsUK4n4I5UjHQ=="
MESSAGE_BYTES=MESSAGE.encode('ascii')
kh = hmac.new(KEY_BYTES, MESSAGE_BYTES, hashlib.sha512).hexdigest()

def encryptDecrypt(input):
	key = ['K', 'C', 'Q'] #Can be any chars, and any size array
	output = []
	
	for i in range(len(input)):
		xor_num = ord(input[i]) ^ ord(key[i % len(key)])
		output.append(chr(xor_num))

	return ''.join(output)


def main():
        print("")
        print("km :"+MASTER_KEY);
        print("")
        
        kh = hmac.new(KEY_BYTES, MESSAGE_BYTES, hashlib.sha512).hexdigest();
        print("kh :"+kh);
        print("")
        
	encrypted = encryptDecrypt(kh);
	print("Ke :"+encrypted);
	print("")
	
	decrypted = encryptDecrypt(encrypted);
	print("kd :"+decrypted);
	print("")

	pass


if __name__ == '__main__':
	main()
