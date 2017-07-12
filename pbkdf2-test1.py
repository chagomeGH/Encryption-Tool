# -*- coding: utf-8 -*-
"""
    pbkdf2
    ~~~~~~
    PBKDF2 implementation for Python.
    UWB Division of Computing and Software Systems  
    CSS 337 Secure Systems -- Winter 2016
    Mariana Chagoyan 
    Encryption Tool -- Masterkey(Km) from --> PBKDF2 
    
    Description:
    Derive a Master key(Km) of 256-bits/32 bytes size from a PBKDF2 key derivation function 
    Required inputs for the KDF: 
    1. sha-512 hashing function of 256 bits/32 bytes size
    2. 32 bytes of salt (generated from a cryptographically random source)
    3. Appropriate iteration count  

    c) Tests how many passwrods can be done under a second include your password


    Km = PBKDF2 (Password, Salt, iterations, key Len, hashfunc)
    Password = master password from which a derived key is generated
    
(Function of two parameters with output length hLen (e.g. a keyed HMAC)
    Salt = sequence of bits, known as a cryptographic salt
    Iterations = number of iterations desired
    Key Len = desired length of the derived key
    Example usage:

    >>> pbkdf2_hex('what i want to hash', 'the random salt')
    'fa7cc8a2b0a932f8e6ea42f9787e9d36e592e0c222ada6a9'

"""

import hmac
import hashlib
import uuid
import random
from struct import Struct
from operator import xor
from itertools import izip, starmap

_pack_int = Struct('>I').pack

password = b'MaStErPaSsWoRd'
salt = uuid.uuid4().hex
iterations = 70000
hashfunc = hashlib.sha512
keylen = 32


def pbkdf2_hex(password, salt, iterations, keylen, hashfunc):
    """Like :func:`pbkdf2_bin` but returns a hex encoded string."""
    return pbkdf2_bin(password, salt, iterations, keylen, hashfunc).encode('hex')


def pbkdf2_bin(password, salt, iterations, keylen, hashfunc):
    """Returns a binary digest for the PBKDF2 hash algorithm of `data`
    with the given `salt`.  It iterates `iterations` time and produces a
    key of `keylen` bytes.  By default SHA-2 is used as hash function,
    a different hashlib `hashfunc` can be provided.
    """
    hashfunc = hashfunc or hashlib.sha512
    mac = hmac.new(password, None, hashfunc)
    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())
    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        Km = u = _pseudorandom(salt + _pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            Km = starmap(xor, izip(Km, u))
        buf.extend(Km)
    return ''.join(map(chr, buf))[:keylen]

def main():
    Km = pbkdf2_hex(password, salt, iterations, keylen, hashfunc);
    print(" Master key Derivation from a PBKDF2 key derivation function:");
    print ' Km         = %s' % Km
    print ' Password   = %s' % password
    print ' Salt       = %s ' % salt
    print ' Iterations = %d' %iterations
    print ' keylen     = %s ' % keylen
    print(" (keylen of 16 contains 32 bytes which equals the first 256 bits of key.");
    pass

if __name__ == '__main__':
    main()

 
