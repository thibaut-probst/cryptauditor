---
noteId: "7581ead0a62611edbb69cfa0fbbde037"
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
Hash time: 0.009ms
```
```
$ python3 cryptauditor.py --hash SHA3-512 -d 10MB -r 10
Performing 10 rounds of SHA3-512 hash on 10MB of random data
Hash time: 66.972ms
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
1 - SHA2-512 - 2.734ms (+0.0ms)
2 - SHA2-384 - 2.886ms (+0.152ms)
3 - SHA3-224 - 3.607ms (+0.873ms)
4 - SHA3-256 - 3.618ms (+0.884ms)
5 - SHA2-224 - 4.276ms (+1.542ms)
6 - SHA2-256 - 4.465ms (+1.731ms)
7 - SHA3-384 - 4.729ms (+1.995ms)
8 - SHA3-512 - 6.921ms (+4.187ms)
```
```
$ python3 cryptauditor.py -c AES-CTR
Performing 1000 rounds of AES encryption and decryption in CTR mode with a 256-bit random key on 1KB of random data
Encryption time: 0.005ms
Decryption time: 0.005ms
```
```
$ python3 cryptauditor.py -c AES-GCM -k 128 -d 10MB -r 100 -u us
Performing 100 rounds of AES encryption and decryption in GCM mode with a 128-bit random key on 10MB of random data
Encryption time: 19036.628us
Decryption time: 19007.448us
```
```
$ python3 cryptauditor.py -c RSA -d 470B -k 4096 
Performing 1000 rounds of RSA-OAEP encryption and decryption with a 4096-bit random key on 470B of random data
Encryption time: 1.101ms
Decryption time: 7.388ms
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
1 - AES-ECB - 9.79ms (+0.0ms)
2 - AES-CTR - 18.692ms (+8.902ms)
3 - AES-GCM - 20.48ms (+10.69ms)
4 - AES-OFB - 23.69ms (+13.9ms)
5 - AES-CBC - 25.161ms (+15.371ms)
6 - AES-OCB - 28.259ms (+18.469ms)
7 - AES-CCM - 40.697ms (+30.907ms)
8 - AES-EAX - 41.144ms (+31.354ms)
9 - AES-SIV - 41.466ms (+31.676ms)
10 - AES-CFB - 272.109ms (+262.319ms)
Decryption speed ranking:
1 - AES-ECB - 9.12ms (+0.0ms)
2 - AES-CTR - 18.368ms (+9.248ms)
3 - AES-GCM - 20.482ms (+11.362ms)
4 - AES-OFB - 23.507ms (+14.387ms)
5 - AES-CBC - 25.331ms (+16.211ms)
6 - AES-OCB - 40.647ms (+31.527ms)
7 - AES-CCM - 40.727ms (+31.607ms)
8 - AES-EAX - 40.907ms (+31.787ms)
9 - AES-SIV - 41.805ms (+32.685ms)
10 - AES-CFB - 260.068ms (+250.948ms)
```
