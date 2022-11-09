---
noteId: "f0d94060603b11eda774b3b2f4b1c528"
tags: []

---

# cryptauditor
![Python3.10](https://camo.githubusercontent.com/2eeb8947056ba0c1c3b1f9015ce807d0f0f462f99dce4c6acdcc7874f27b1820/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f707974686f6e2d332e31302d626c75652e737667)  
---  
A cryptography audit tool to measure algorithms speed.  
Supported cipher algorithms currently include: AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-CCM, AES-GCM, AES-EAX, AES-SIV, AES-OCB and RSA-OAEP.  
It is possible to pass AES-ALL as cipher algorithm to try all AES modes and provide a ranking.  
It is also possible to pass SYMMETRIC-ALL as cipher algorithm to try all symmetric ciphers and provide a ranking.  
Supported hash algorithms currently include: SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512.  
It is possible to pass HASH-ALL as hash algorithm to try all hash algorithms and provide a ranking.  
More algorithms and features will come.  
***cryptauditor*** uses Python and the [PyCryptodome](https://pycryptodome.readthedocs.io) library.  
Performance is measured with the [time](https://docs.python.org/3/library/time.html) library using the [perf_counter()](https://docs.python.org/3/library/time.html#time.perf_counter) and by temporarily disabling the [garbage collector](https://docs.python.org/3/library/gc.html).

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
usage: cryptauditor.py [-h] [--cipher CIPHER] [--hash HASH] [--key_length KEY_LENGTH] [--data_size DATA_SIZE] [--rounds ROUNDS] [--unit UNIT]

options:
  -h, --help            show this help message and exit
  --cipher CIPHER, -c CIPHER
                        Cipher algorithm and mode of operation (AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-CCM, AES-GCM, AES-EAX, AES-SIV, AES-OCB, CHACHA20, SALSA20, RSA-OAEP).
                        AES-ALL can be passed to test and compare all modes of operation on AES. SYMMETRIC-ALL can be passed to test and compare all symmetric cipher algorithms.
  --hash HASH           Hash algorithm (SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, TUPLEHASH128, TUPLEHASH256). HASH-ALL can be passed to test and
                        compare all hash algorithms.
  --key_length KEY_LENGTH, -k KEY_LENGTH
                        Key length in bits (must be a multiple of 8, default: 256)
  --data_size DATA_SIZE, -d DATA_SIZE
                        Data size in B, KB or MB (e.g. 10MB, default: 1KB)
  --rounds ROUNDS, -r ROUNDS
                        Number of encryption and decryption rounds to be computed (default: 1000)
  --unit UNIT, -u UNIT  Time unit (ns, us, ms or s, default: ms)
```
            
## Examples
```
$ python3 cryptauditor.py --hash SHA2-256
Performing 1000 rounds of SHA-256 hash on 1KB of random data
Hash time: 0.015ms
```
```
$ python3 cryptauditor.py --hash SHA3-512 -d 10MB -r 10
Performing 10 rounds of SHA3-512 hash on 10MB of random data
Hash time: 62.856ms
```
```
$ python3 cryptauditor.py --hash HASH-ALL -d 1MB -r 100
Performing 100 rounds of SHA-224 hash on 1MB of random data
Performing 100 rounds of SHA-256 hash on 1MB of random data
Performing 100 rounds of SHA-384 hash on 1MB of random data
Performing 100 rounds of SHA-512 hash on 1MB of random data
Performing 100 rounds of SHA3-224 hash on 1MB of random data
Performing 100 rounds of SHA3-256 hash on 1MB of random data
Performing 100 rounds of SHA3-384 hash on 1MB of random data
Performing 100 rounds of SHA3-512 hash on 1MB of random data
Hash speed ranking:
1 - SHA3-224 (+0.0ms)
2 - SHA3-256 (+0.228ms)
3 - SHA3-384 (+1.409ms)
4 - SHA2-384 (+1.414ms)
5 - SHA2-512 (+1.502ms)
6 - SHA2-224 (+3.176ms)
7 - SHA3-512 (+3.223ms)
8 - SHA2-256 (+3.292ms)
```
```
$ python3 cryptauditor.py -c AES-CTR
Performing 1000 rounds of AES encryption and decryption in CTR mode with a 256-bit random key on 1KB of random data
Encryption time: 0.007ms
Decryption time: 0.006ms
```
```
$ python3 cryptauditor.py -c AES-GCM -k 128 -d 10MB -r 100 -u us
Performing 100 rounds of AES encryption and decryption in GCM mode with a 128-bit random key on 10MB of random data
Encryption time: 70138.383us
Decryption time: 69946.606us
```
```
$ python3 cryptauditor.py -c RSA -d 470B -k 4096 
Performing 1000 rounds of RSA-OAEP encryption and decryption with a 4096-bit random key on 470B of random data
Encryption time: 1.255ms
Decryption time: 6.829ms
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
1 - AES-ECB (+0.0ms)
2 - AES-CTR (+10.433ms)
3 - AES-OFB (+12.472ms)
4 - AES-CBC (+13.222ms)
5 - AES-OCB (+17.161ms)
6 - AES-SIV (+30.667ms)
7 - AES-CCM (+32.509ms)
8 - AES-EAX (+32.534ms)
9 - AES-GCM (+63.369ms)
10 - AES-CFB (+247.993ms)
Decryption speed ranking:
1 - AES-ECB (+0.0ms)
2 - AES-CTR (+11.742ms)
3 - AES-CBC (+11.954ms)
4 - AES-OFB (+13.642ms)
5 - AES-OCB (+31.529ms)
6 - AES-SIV (+31.607ms)
7 - AES-EAX (+32.973ms)
8 - AES-CCM (+33.684ms)
9 - AES-GCM (+63.806ms)
10 - AES-CFB (+246.551ms)
```
