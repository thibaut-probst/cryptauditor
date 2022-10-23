# cryptauditor
![Python3.10](https://camo.githubusercontent.com/2eeb8947056ba0c1c3b1f9015ce807d0f0f462f99dce4c6acdcc7874f27b1820/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f707974686f6e2d332e31302d626c75652e737667)  
---  
A cryptography audit tool to measure algorithms speed.  
Supported algorithms currently include: AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-CCM, AES-GCM, AES-EAX, AES-SIV, AES-OCB and RSA-OAEP.  
More algorithms will come (stream ciphers, hash functions, key exchanges...).  
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
usage: cryptauditor.py [-h] --cipher CIPHER [--key_length KEY_LENGTH] [--data_size DATA_SIZE] [--rounds ROUNDS] [--unit UNIT]

options:
  -h, --help            show this help message and exit
  --cipher CIPHER, -c CIPHER
                        Cipher algorithm and mode of operation (AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-CCM, AES-GCM, AES-
                        EAX, AES-SIV, AES-OCB, RSA-OAEP
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
