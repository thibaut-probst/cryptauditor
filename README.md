# cryptauditor
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue) 
---  
A cryptography audit tool to measure algorithms speed.   
***cryptauditor*** uses Python and the [PyCryptodome](https://pycryptodome.readthedocs.io) library.  
Performance is measured with the [time](https://docs.python.org/3/library/time.html) library using the [perf_counter()](https://docs.python.org/3/library/time.html#time.perf_counter) and by temporarily disabling the [garbage collector](https://docs.python.org/3/library/gc.html).

## Features

* Encryption and decryption speed measurement and ranking for main AES modes, ChaCha20, Salsa20 and RSA:  
    * Supported cipher algorithms currently include: AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-CCM, AES-GCM, AES-EAX, AES-SIV, AES-OCB, ChaCha20, Salsa20 and RSA-OAEP.  
    * It is possible to pass AES-ALL as cipher algorithm to try all AES modes and provide a ranking.  
    * It is also possible to pass SYMMETRIC-ALL as cipher algorithm to try all symmetric ciphers and provide a ranking.
* Key encapsulation and decapsulation speed measurement and ranking for post-quantum ML-KEM-512, ML-KEM-768 and ML-KEM-1024. 
* Hashing speed measurement and ranking for SHA family:  
    * Supported hash algorithms currently include: SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA3-224, SHA3-256, SHA3-384 and SHA3-512.  
    * It is possible to pass HASH-ALL as hash algorithm to try all hash algorithms and provide a ranking.  
    * More algorithms and features will come.  
* Signature speed measurement and ranking:
    * Supported signature schemes currently include: RSA-PSS, ECDSA and EdDSA.  
    * It is possible to pass SIGN-ALL as signature scheme to try all signature schemes and provide a ranking. 

## Pre-requisites

Make sure you have [Python 3.10 or higher](https://www.python.org/downloads/) installed.

## Installation 

#### 1. Clone the repository to your working directory 
```
$ git clone https://github.com/thibaut-probst/cryptauditor.git
$ cd cryptauditor/
```
#### 2. Install the requirements 
```
$ pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

## Usage 

You can display ***cryptauditor*** startup parameters information by using the --help argument: 

```
$ python3 cryptauditor.py -h
usage: cryptauditor.py [-h] [--cipher CIPHER] [--kem KEM] [--hash HASH] [--signature SIGNATURE] [--key_length KEY_LENGTH] [--data_size DATA_SIZE]
                       [--rounds ROUNDS] [--unit UNIT]

options:
  -h, --help            show this help message and exit
  --cipher, -c CIPHER   Cipher algorithm and mode of operation (AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-CCM, AES-GCM, AES-EAX, AES-SIV, AES-OCB,
                        CHACHA20, SALSA20, RSA-OAEP). AES-ALL can be passed to test and compare all modes of operation on AES. SYMMETRIC-ALL can be passed to
                        test and compare all symmetric cipher algorithms.
  --kem, -K KEM         KEM algorithm (ML-KEM-512, ML-KEM-768, ML-KEM-1024).
  --hash HASH           Hash algorithm (SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512). HASH-ALL can be passed to test and
                        compare all hash algorithms.
  --signature, -s SIGNATURE
                        Signature scheme (RSA-PSS, ECDSA, EdDSA). SIGN-ALL can be passed to test and compare all signature schemes
  --key_length, -k KEY_LENGTH
                        Key length in bits (must be a multiple of 8, default: 256)
  --data_size, -d DATA_SIZE
                        Data size in B, KB or MB (e.g. 10MB, default: 1KB)
  --rounds, -r ROUNDS   Number of encryption and decryption rounds to be computed (default: 1000)
  --unit, -u UNIT       Time unit (ns, us, ms or s, default: ms)
```
            
## Examples
```
$ python3 cryptauditor.py --hash SHA-256
Performing 1000 rounds of SHA-256 hash on 1KB of random data
Hash time: 0.004ms
```
```
$ python3 cryptauditor.py --hash SHA3-512 -d 10MB -r 10
Performing 10 rounds of SHA3-512 hash on 10MB of random data
Hash time: 20.648ms
```
```
$ python3 cryptauditor.py --hash HASH-ALL -d 1MB -r 100
Performing 100 rounds of SHA-224 hash on '1MB' of random data
Performing 100 rounds of SHA-256 hash on '1MB' of random data
Performing 100 rounds of SHA-384 hash on '1MB' of random data
Performing 100 rounds of SHA-512 hash on '1MB' of random data
Performing 100 rounds of SHA3-224 hash on '1MB' of random data
Performing 100 rounds of SHA3-256 hash on '1MB' of random data
Performing 100 rounds of SHA3-384 hash on '1MB' of random data
Performing 100 rounds of SHA3-512 hash on '1MB' of random data
Hash speed ranking:
1 - SHA3-224 - 1.059ms (+0.0ms)
2 - SHA3-256 - 1.117ms (+0.058ms)
3 - SHA2-512 - 1.438ms (+0.379ms)
4 - SHA2-384 - 1.447ms (+0.388ms)
5 - SHA3-384 - 1.461ms (+0.402ms)
6 - SHA3-512 - 2.106ms (+1.047ms)
7 - SHA2-224 - 2.257ms (+1.198ms)
8 - SHA2-256 - 2.264ms (+1.205ms)
```
```
$ python3 cryptauditor.py -c AES-CTR
Performing 1000 rounds of AES encryption and decryption in CTR mode with a 256-bit random key on 1KB of random data
Encryption time: 0.004ms
Decryption time: 0.003ms
```
```
$ python3 cryptauditor.py -c AES-GCM -k 128 -d 10MB -r 100 -u us
Performing 100 rounds of AES encryption and decryption in GCM mode with a 128-bit random key on 10MB of random data
Encryption time: 40952.393us
Decryption time: 40970.0us
```
```
$ python3 cryptauditor.py -c RSA -d 470B -k 4096 
Performing 1000 rounds of RSA-OAEP encryption and decryption with a 4096-bit random key on 470B of random data
Encryption time: 0.919ms
Decryption time: 8.427ms
```
```
$ python3 cryptauditor.py -c aes-all -d 10MB -r 10
Performing 10 rounds of AES encryption and decryption in ECB mode with a 256-bit random key on 10MB of random data
Performing 10 rounds of AES encryption and decryption in CBC mode with a 256-bit random key on 10MB of random data
Performing 10 rounds of AES encryption and decryption in CFB mode with a 256-bit random key on 10MB of random data
Performing 10 rounds of AES encryption and decryption in OFB mode with a 256-bit random key on 10MB of random data
Performing 10 rounds of AES encryption and decryption in CTR mode with a 256-bit random key on 10MB of random data
Performing 10 rounds of AES encryption and decryption in CCM mode with a 256-bit random key on 10MB of random data
Performing 10 rounds of AES encryption and decryption in GCM mode with a 256-bit random key on 10MB of random data
Performing 10 rounds of AES encryption and decryption in EAX mode with a 256-bit random key on 10MB of random data
Performing 10 rounds of AES encryption and decryption in SIV mode with a 256-bit random key on 10MB of random data
Performing 10 rounds of AES encryption and decryption in OCB mode with a 256-bit random key on 10MB of random data
Encryption speed ranking:
1 - AES-CTR - 29.072ms (+0.0ms)
2 - AES-ECB - 30.306ms (+1.234ms)
3 - AES-OFB - 32.566ms (+3.494ms)
4 - AES-OCB - 36.362ms (+7.29ms)
5 - AES-CBC - 40.523ms (+11.451ms)
6 - AES-SIV - 48.488ms (+19.416ms)
7 - AES-GCM - 50.155ms (+21.083ms)
8 - AES-EAX - 62.255ms (+33.183ms)
9 - AES-CCM - 62.414ms (+33.342ms)
10 - AES-CFB - 496.742ms (+467.67ms)
Decryption speed ranking:
1 - AES-CTR - 29.152ms (+0.0ms)
2 - AES-ECB - 30.916ms (+1.764ms)
3 - AES-OFB - 32.571ms (+3.419ms)
4 - AES-CBC - 32.878ms (+3.726ms)
5 - AES-OCB - 37.854ms (+8.702ms)
6 - AES-SIV - 48.436ms (+19.284ms)
7 - AES-GCM - 50.119ms (+20.967ms)
8 - AES-EAX - 62.258ms (+33.106ms)
9 - AES-CCM - 62.79ms (+33.638ms)
10 - AES-CFB - 465.109ms (+435.957ms)
```
```
$ python3 cryptauditor.py -c SYMMETRIC-ALL
Performing 1000 rounds of AES encryption and decryption in ECB mode with a 256-bit random key on 1KB of random data
Performing 1000 rounds of AES encryption and decryption in CBC mode with a 256-bit random key on 1KB of random data
Performing 1000 rounds of AES encryption and decryption in CFB mode with a 256-bit random key on 1KB of random data
Performing 1000 rounds of AES encryption and decryption in OFB mode with a 256-bit random key on 1KB of random data
Performing 1000 rounds of AES encryption and decryption in CTR mode with a 256-bit random key on 1KB of random data
Performing 1000 rounds of AES encryption and decryption in CCM mode with a 256-bit random key on 1KB of random data
Performing 1000 rounds of AES encryption and decryption in GCM mode with a 256-bit random key on 1KB of random data
Performing 1000 rounds of AES encryption and decryption in EAX mode with a 256-bit random key on 1KB of random data
Performing 1000 rounds of AES encryption and decryption in SIV mode with a 256-bit random key on 1KB of random data
Performing 1000 rounds of AES encryption and decryption in OCB mode with a 256-bit random key on 1KB of random data
Performing 1000 rounds of CHACHA20 encryption and decryption with a 256-bit random key on 1KB of random data
Performing 1000 rounds of SALSA20 encryption and decryption with a 256-bit random key on 1KB of random data
Encryption speed ranking:
1 - CHACHA20 - 0.002ms (+0.0ms)
2 - AES-CTR - 0.003ms (+0.001ms)
3 - SALSA20 - 0.003ms (+0.001ms)
4 - AES-ECB - 0.004ms (+0.002ms)
5 - AES-CBC - 0.004ms (+0.002ms)
6 - AES-OFB - 0.004ms (+0.002ms)
7 - AES-OCB - 0.006ms (+0.004ms)
8 - AES-GCM - 0.009ms (+0.007ms)
9 - AES-CCM - 0.011ms (+0.009ms)
10 - AES-EAX - 0.013ms (+0.011ms)
11 - AES-CFB - 0.046ms (+0.044ms)
12 - AES-SIV - 0.046ms (+0.044ms)
Decryption speed ranking:
1 - CHACHA20 - 0.002ms (+0.0ms)
2 - AES-ECB - 0.003ms (+0.001ms)
3 - AES-CTR - 0.003ms (+0.001ms)
4 - SALSA20 - 0.003ms (+0.001ms)
5 - AES-CBC - 0.004ms (+0.002ms)
6 - AES-OFB - 0.004ms (+0.002ms)
7 - AES-OCB - 0.01ms (+0.008ms)
8 - AES-GCM - 0.013ms (+0.011ms)
9 - AES-CCM - 0.015ms (+0.013ms)
10 - AES-EAX - 0.018ms (+0.016ms)
11 - AES-CFB - 0.044ms (+0.042ms)
12 - AES-SIV - 0.051ms (+0.049ms)
```
```
$ python3 cryptauditor.py -s EDDSA
Performing 1000 rounds of EdDSA signature and verification with a 256-bit (Ed25519) elliptic curve on 1KB of random data hashed with SHA-512
Signature time: 0.102ms
Verification time: 0.362ms
```
```
$ python3 cryptauditor.py -s SIGN-ALL -k 3072 -r 10000
Performing 10000 rounds of RSA-PSS signature and verification with a 3072-bit random key on 1KB of random data hashed with SHA-256
Performing 10000 rounds of ECDSA signature and verification with a 256-bit (P-256) elliptic curve on 1KB of random data hashed with SHA-256
Performing 10000 rounds of EdDSA signature and verification with a 256-bit (Ed25519) elliptic curve on 1KB of random data hashed with SHA-512
Signature speed ranking:
1 - EdDSA - 0.104ms (+0.0ms)
2 - ECDSA - 0.135ms (+0.031ms)
3 - RSA-PSS - 4.158ms (+4.054ms)
Verification speed ranking:
1 - EdDSA - 0.337ms (+0.0ms)
2 - ECDSA - 0.382ms (+0.045ms)
3 - RSA-PSS - 0.52ms (+0.183ms)
```
```
$ python3 cryptauditor.py -K ML-KEM-512 -r 1000 -u us
Performing 1000 rounds of ML-KEM-512 encapsulation and decapsulation
Encapsulation time: 14.802us
Decapsulation time: 19.28us
```
```
$ python3 cryptauditor.py -K ML-KEM-768 -r 1000 -u us
Performing 1000 rounds of ML-KEM-768 encapsulation and decapsulation
Encapsulation time: 23.428us
Decapsulation time: 29.665us
```
```
$ python3 cryptauditor.py -K ML-KEM-1024 -r 1000 -u us
Performing 1000 rounds of ML-KEM-1024 encapsulation and decapsulation
Encapsulation time: 34.615us
Decapsulation time: 42.664us
```