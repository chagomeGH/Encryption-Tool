# Encryption-Tool
Applied Cryptography tools to encrypt and derive keys using HMAC, PBKDF2 and SHA-512

1. Derive a Km (master key) of 256-bits/32 bytes size from a PBKDF2 key derivation function 
Required inputs to the KDF: 
•	sha-512 hashing function of 256 bits/32 bytes size
•	32 bytes of salt (generated from a cryptographically random source)
•	Appropriate iteration count. (100,000 is suggested) 

2.	Create an Ke (encryption key) and Kh (HMAC key) from Km (master key) using an HMAC function
Use two different strings or other different input as the salt argument. 
Use a sha-512 HMAC, and use the first 256 bits as your keys.

3.  Generate a random initialization vector (IV) from a cryptographically random source 
with size  equal to the block size of AES-256 encryption.

4. Encrypt your input message using 
a) AES 256, 
b) IV 
c) Ke 
d) Chaining mode CBC 
e) Default-padding mode
