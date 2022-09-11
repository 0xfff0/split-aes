## split-aes

"Speed up" AES CBC by splitting up large input file into smaller chunks and encrypt/decrypt in parallel:

- Chunk size 32M (arbitrary);
- Each chunk uses a random IV and key salt, both of which are prefixed to the final encrypted blob;
- All chunks share the same passphrase, key derivation is PBKDF2 with 10000 iterations.

This algorithm usually runs faster than single threaded AES CBC; however, it is unclear whether it has the same cryptographic strength. The original intention of this tool is to have *some* file level security in an already secured file system, the correctness and strength of the en/decryption procedures are not guaranteed.

### To build:

Install `libssl-dev`, or whatever your distribution specific package for libcrypto might be, then:

`gcc main.c -lcrypto -lpthread`

### To run:

Encrypt: `./a.out -i <input file> -o <output file> -j <job count> enc`

Decrypt: `./a.out -i <input file> -o <output file> -j <job count> dec`
