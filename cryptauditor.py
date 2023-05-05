from argparse import ArgumentParser
from os import urandom
from re import search
from time import perf_counter
import gc
from Crypto.Hash import SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20, Salsa20
from Crypto.PublicKey import RSA, ECC
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss, DSS, eddsa
from binascii import hexlify

def sha_224(gc_is_enabled, data, n_rounds):
    '''
    SHA-224 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                avg_hash_time (float): return hash time or False if failure
    '''
    print(
        f'Performing {n_rounds} rounds of SHA-224 hash on {data_size} of random data'
    )
    avg_hash_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Hash
            start = perf_counter()
            h = SHA224.new(data)
            end = perf_counter()
            if (len(h.digest()) * 8) != 224:
                print(f'Error: hash output length is not 224-bit long')
                return (False, False)
            avg_hash_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return False
    finally:
        if gc_is_enabled:
            gc.enable()
        return avg_hash_time/n_rounds

def sha_256(gc_is_enabled, data, n_rounds):
    '''
    SHA-256 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                avg_hash_time (float): return hash time or False if failure
    '''
    print(
        f'Performing {n_rounds} rounds of SHA-256 hash on {data_size} of random data'
    )
    avg_hash_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Hash
            start = perf_counter()
            h = SHA256.new(data)
            end = perf_counter()
            if (len(h.digest()) * 8) != 256:
                print(f'Error: hash output length is not 256-bit long')
                return (False, False)
            avg_hash_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return False
    finally:
        if gc_is_enabled:
            gc.enable()
        return avg_hash_time/n_rounds

def sha_384(gc_is_enabled, data, n_rounds):
    '''
    SHA-384 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                avg_hash_time (float): return hash time or False if failure
    '''
    print(
        f'Performing {n_rounds} rounds of SHA-384 hash on {data_size} of random data'
    )
    avg_hash_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Hash
            start = perf_counter()
            h = SHA384.new(data)
            end = perf_counter()
            if (len(h.digest()) * 8) != 384:
                print(f'Error: hash output length is not 256-bit long')
                return (False, False)
            avg_hash_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return False
    finally:
        if gc_is_enabled:
            gc.enable()
        return avg_hash_time/n_rounds

def sha_512(gc_is_enabled, data, n_rounds):
    '''
    SHA-512 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                avg_hash_time (float): return hash time or False if failure
    '''
    print(
        f'Performing {n_rounds} rounds of SHA-512 hash on {data_size} of random data'
    )
    avg_hash_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Hash
            start = perf_counter()
            h = SHA512.new(data)
            end = perf_counter()
            if (len(h.digest()) * 8) != 512:
                print(f'Error: hash output length is not 512-bit long')
                return (False, False)
            avg_hash_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return False
    finally:
        if gc_is_enabled:
            gc.enable()
        return avg_hash_time/n_rounds

def sha3_224(gc_is_enabled, data, n_rounds):
    '''
    SHA3-224 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                avg_hash_time (float): return hash time or False if failure
    '''
    print(
        f'Performing {n_rounds} rounds of SHA3-224 hash on {data_size} of random data'
    )
    avg_hash_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Hash
            start = perf_counter()
            h = SHA3_224.new(data=data)
            end = perf_counter()
            if (len(h.digest()) * 8) != 224:
                print(f'Error: hash output length is not 224-bit long')
                return (False, False)
            avg_hash_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return False
    finally:
        if gc_is_enabled:
            gc.enable()
        return avg_hash_time/n_rounds

def sha3_256(gc_is_enabled, data, n_rounds):
    '''
    SHA3-256 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                avg_hash_time (float): return hash time or False if failure
    '''
    print(
        f'Performing {n_rounds} rounds of SHA3-256 hash on {data_size} of random data'
    )
    avg_hash_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Hash
            start = perf_counter()
            h = SHA3_256.new(data=data)
            end = perf_counter()
            if (len(h.digest()) * 8) != 256:
                print(f'Error: hash output length is not 256-bit long')
                return (False, False)
            avg_hash_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return False
    finally:
        if gc_is_enabled:
            gc.enable()
        return avg_hash_time/n_rounds

def sha3_384(gc_is_enabled, data, n_rounds):
    '''
    SHA3-384 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                avg_hash_time (float): return hash time or False if failure
    '''
    print(
        f'Performing {n_rounds} rounds of SHA3-384 hash on {data_size} of random data'
    )
    avg_hash_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Hash
            start = perf_counter()
            h = SHA3_384.new(data=data)
            end = perf_counter()
            if (len(h.digest()) * 8) != 384:
                print(f'Error: hash output length is not 384-bit long')
                return (False, False)
            avg_hash_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return False
    finally:
        if gc_is_enabled:
            gc.enable()
        return avg_hash_time/n_rounds

def sha3_512(gc_is_enabled, data, n_rounds):
    '''
    SHA3-512 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                avg_hash_time (float): return hash time or False if failure
    '''
    print(
        f'Performing {n_rounds} rounds of SHA3-512 hash on {data_size} of random data'
    )
    avg_hash_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Hash
            start = perf_counter()
            h = SHA3_512.new(data=data)
            end = perf_counter()
            if (len(h.digest()) * 8) != 512:
                print(f'Error: hash output length is not 512-bit long')
                return (False, False)
            avg_hash_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return False
    finally:
        if gc_is_enabled:
            gc.enable()
        return avg_hash_time/n_rounds

def aes_ecb(gc_is_enabled, key, data, n_rounds):
    '''
    AES ECB speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    ''' 
    print(
        f'Performing {n_rounds} rounds of AES encryption and decryption in ECB mode with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            cipher1 = AES.new(key, AES.MODE_ECB)
            start = perf_counter()
            ciphertext = cipher1.encrypt(pad(data, AES.block_size))
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = AES.new(key, AES.MODE_ECB)
            # Decryption
            start = perf_counter()
            plaintext = unpad(cipher2.decrypt(ciphertext), AES.block_size)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def aes_cbc(gc_is_enabled, key, data, n_rounds):
    '''
    AES CBC speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    ''' 
    print(
        f'Performing {n_rounds} rounds of AES encryption and decryption in CBC mode with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            iv = get_random_bytes(AES.block_size)
            cipher1 = AES.new(key, AES.MODE_CBC, iv)
            start = perf_counter()
            ciphertext = cipher1.encrypt(pad(data, AES.block_size))
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = AES.new(key, AES.MODE_CBC, iv)
            # Decryption
            start = perf_counter()
            plaintext = unpad(cipher2.decrypt(ciphertext), AES.block_size)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def aes_cfb(gc_is_enabled, key, data, n_rounds):
    '''
    AES CFB speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    ''' 
    print(
        f'Performing {n_rounds} rounds of AES encryption and decryption in CFB mode with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            iv = get_random_bytes(AES.block_size)
            cipher1 = AES.new(key, AES.MODE_CFB, iv)
            start = perf_counter()
            ciphertext = cipher1.encrypt(data)
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = AES.new(key, AES.MODE_CFB, iv)
            # Decryption
            start = perf_counter()
            plaintext = cipher2.decrypt(ciphertext)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def aes_ofb(gc_is_enabled, key, data, n_rounds):
    '''
    AES OFB speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    print(
        f'Performing {n_rounds} rounds of AES encryption and decryption in OFB mode with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            iv = get_random_bytes(AES.block_size)
            cipher1 = AES.new(key, AES.MODE_OFB, iv)
            start = perf_counter()
            ciphertext = cipher1.encrypt(data)
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = AES.new(key, AES.MODE_OFB, iv)
            # Decryption
            start = perf_counter()
            plaintext = cipher2.decrypt(ciphertext)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def aes_ctr(gc_is_enabled, key, data, n_rounds):
    '''
    AES CTR speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    print(
        f'Performing {n_rounds} rounds of AES encryption and decryption in CTR mode with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            ctr_iv = get_random_bytes(AES.block_size)
            ctr = Counter.new(
                128, initial_value=int(hexlify(ctr_iv), AES.block_size)
            )
            cipher1 = AES.new(key, AES.MODE_CTR, counter=ctr)
            start = perf_counter()
            ciphertext = cipher1.encrypt(data)
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = AES.new(key, AES.MODE_CTR, counter=ctr)
            # Decryption
            start = perf_counter()
            plaintext = cipher2.decrypt(ciphertext)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def aes_ccm(gc_is_enabled, key, data, n_rounds):
    '''
    AES CCM speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    print(
        f'Performing {n_rounds} rounds of AES encryption and decryption in CCM mode with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            cipher1 = AES.new(key, AES.MODE_CCM)
            start = perf_counter()
            ciphertext, tag = cipher1.encrypt_and_digest(data)
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = AES.new(key, AES.MODE_CCM, cipher1.nonce)
            # Decryption
            start = perf_counter()
            plaintext = cipher2.decrypt_and_verify(ciphertext, tag)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def aes_gcm(gc_is_enabled, key, data, n_rounds):
    '''
    AES GCM speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    print(
        f'Performing {n_rounds} rounds of AES encryption and decryption in GCM mode with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            cipher1 = AES.new(key, AES.MODE_GCM)
            start = perf_counter()
            ciphertext, tag = cipher1.encrypt_and_digest(data)
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = AES.new(key, AES.MODE_GCM, cipher1.nonce)
            # Decryption
            start = perf_counter()
            plaintext = cipher2.decrypt_and_verify(ciphertext, tag)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def aes_siv(gc_is_enabled, key, data, n_rounds):
    '''
    AES SIV speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    print(
        f'Performing {n_rounds} rounds of AES encryption and decryption in SIV mode with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            nonce = get_random_bytes(AES.block_size)
            cipher1 = AES.new(key, AES.MODE_SIV, nonce=nonce)
            start = perf_counter()
            ciphertext, tag = cipher1.encrypt_and_digest(data)
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = AES.new(key, AES.MODE_SIV, cipher1.nonce)
            # Decryption
            start = perf_counter()
            plaintext = cipher2.decrypt_and_verify(ciphertext, tag)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def aes_eax(gc_is_enabled, key, data, n_rounds):
    '''
    AES EAX speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    print(
        f'Performing {n_rounds} rounds of AES encryption and decryption in EAX mode with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            cipher1 = AES.new(key, AES.MODE_EAX)
            start = perf_counter()
            ciphertext, tag = cipher1.encrypt_and_digest(data)
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = AES.new(key, AES.MODE_EAX, cipher1.nonce)
            # Decryption
            start = perf_counter()
            plaintext = cipher2.decrypt_and_verify(ciphertext, tag)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def aes_ocb(gc_is_enabled, key, data, n_rounds):
    '''
    AES OCB speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    print(
        f'Performing {n_rounds} rounds of AES encryption and decryption in OCB mode with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            cipher1 = AES.new(key, AES.MODE_OCB)
            start = perf_counter()
            ciphertext, tag = cipher1.encrypt_and_digest(data)
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = AES.new(key, AES.MODE_OCB, cipher1.nonce)
            # Decryption
            start = perf_counter()
            plaintext = cipher2.decrypt_and_verify(ciphertext, tag)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def chacha20(gc_is_enabled, key, data, n_rounds):
    '''
    CHACHA20 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    key_len = len(key) * 8
    if key_len != 256:
        print(f'ChaCha20 key length must be equal to 256')
        return (False, False)
    print(
        f'Performing {n_rounds} rounds of CHACHA20 encryption and decryption with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            cipher1 = ChaCha20.new(key=key)
            start = perf_counter()
            ciphertext = cipher1.encrypt(data)
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = ChaCha20.new(key=key, nonce=cipher1.nonce)
            # Decryption
            start = perf_counter()
            plaintext = cipher2.decrypt(ciphertext)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def salsa20(gc_is_enabled, key, data, n_rounds):
    '''
    SALSA20 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key (str): key
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    key_len = len(key) * 8
    if (key_len != 256) and (key_len != 128):
        print(f'Salsa20 key length must be equal to 128 or 256')
        return (False, False)
    print(
        f'Performing {n_rounds} rounds of SALSA20 encryption and decryption with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        for i in range(n_rounds):
            # Encryption
            cipher1 = Salsa20.new(key=key)
            start = perf_counter()
            ciphertext = cipher1.encrypt(data)
            end = perf_counter()
            avg_enc_time += end - start
            cipher2 = Salsa20.new(key=key, nonce=cipher1.nonce)
            # Decryption
            start = perf_counter()
            plaintext = cipher2.decrypt(ciphertext)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def rsa_oaep(gc_is_enabled, key_len, data, n_rounds):
    '''
    RSA OAEP speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key_len (int): key length
                data_len (int): plaintext data length
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    data_len = len(data)
    if key_len < 1024:
        print(f'RSA key length must be greater or equal to 1024')
        return (False, False)
    elif data_len > ( key_len / 8 - 42 ):
        print(f'Plaintext data size must be less or equal than {int(key_len / 8 - 42)}B (RSA key length minus 42-byte OAEP padding data)')
        return (False, False)
    print(
        f'Performing {n_rounds} rounds of RSA-OAEP encryption and decryption with a {key_len}-bit random key on {data_size} of random data'
    )
    avg_enc_time = 0
    avg_dec_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        private_key = RSA.generate(key_len)
        public_key = private_key.publickey()
        for i in range(n_rounds):
            # Encryption
            cipher_rsa = PKCS1_OAEP.new(public_key)
            start = perf_counter()
            ciphertext = cipher_rsa.encrypt(data)
            end = perf_counter()
            avg_enc_time += end - start
            # Decryption
            cipher_rsa = PKCS1_OAEP.new(private_key)
            start = perf_counter()
            plaintext = cipher_rsa.decrypt(ciphertext)
            end = perf_counter()
            if plaintext != data:
                print(f'Error: decrypted ciphertext does not match initial plaintext!')
                return (False, False)
            avg_dec_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_enc_time/n_rounds, avg_dec_time/n_rounds)

def rsa_pss(gc_is_enabled, key_len, data, n_rounds):
    '''
    RSA PSS speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                key_len (int): key length
                data_len (int): plaintext data length
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    data_len = len(data)
    if key_len < 1024:
        print(f'RSA key length must be greater or equal to 1024')
        return (False, False)
    print(
        f'Performing {n_rounds} rounds of RSA-PSS signature and verification with a {key_len}-bit random key on {data_size} of random data hashed with SHA-256'
    )
    avg_sig_time = 0
    avg_ver_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        private_key = RSA.generate(key_len)
        public_key = private_key.publickey()
        signer = pss.new(private_key)
        verifier = pss.new(public_key)
        h = SHA256.new(data)
        for i in range(n_rounds):
            # Signature
            start = perf_counter()
            signature = signer.sign(h)
            end = perf_counter()
            avg_sig_time += end - start
            # Verification
            try:
                start = perf_counter()
                verifier.verify(h, signature)
                end = perf_counter()
            except:
                print(f'Error: signature is not authentic!')
                return (False, False)
            avg_ver_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_sig_time/n_rounds, avg_ver_time/n_rounds)

def ecdsa_256(gc_is_enabled, data, n_rounds):
    '''
    ECDSA P-256 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                data_len (int): plaintext data length
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    data_len = len(data)
    print(
        f'Performing {n_rounds} rounds of ECDSA signature and verification with a 256-bit (P-256) elliptic curve on {data_size} of random data hashed with SHA-256'
    )
    avg_sig_time = 0
    avg_ver_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        private_key = ECC.generate(curve='secp256r1')
        public_key = private_key.public_key()
        signer = DSS.new(private_key, 'fips-186-3')
        verifier = DSS.new(public_key, 'fips-186-3')
        h = SHA256.new(data)
        for i in range(n_rounds):
            # Signature
            start = perf_counter()
            signature = signer.sign(h)
            end = perf_counter()
            avg_sig_time += end - start
            # Verification
            try:
                start = perf_counter()
                verifier.verify(h, signature)
                end = perf_counter()
            except:
                print(f'Error: signature is not authentic!')
                return (False, False)
            avg_ver_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_sig_time/n_rounds, avg_ver_time/n_rounds)

def eddsa_256(gc_is_enabled, data, n_rounds):
    '''
    EdDSA Ed25519 speed measurement function
        
            Parameters:
                gc_is_enabled (bool): indicates if garbage collector is enabled or not
                data_len (int): plaintext data length
                data (str): plaintext data
                n_rounds (int): queue to communicate with receiver thread
            Returns:
                (avg_enc_time, avg_dec_time) (tuple): return encryption and decryption times ((float, float): success, (False, False): failure)
    '''
    data_len = len(data)
    print(
        f'Performing {n_rounds} rounds of EdDSA signature and verification with a 256-bit (Ed25519) elliptic curve on {data_size} of random data hashed with SHA-512'
    )
    avg_sig_time = 0
    avg_ver_time = 0
    # Disable Garbage Collector
    gc.disable()              
    start = 0
    end = 0
    try:
        private_key = ECC.generate(curve='ed25519')
        public_key = private_key.public_key()
        signer = eddsa.new(private_key, 'rfc8032')
        verifier = eddsa.new(public_key, 'rfc8032')
        h = SHA512.new(data)
        for i in range(n_rounds):
            # Signature
            start = perf_counter()
            signature = signer.sign(h)
            end = perf_counter()
            avg_sig_time += end - start
            # Verification
            try:
                start = perf_counter()
                verifier.verify(h, signature)
                end = perf_counter()
            except:
                print(f'Error: signature is not authentic!')
                return (False, False)
            avg_ver_time += end - start
    except Exception as e:
        print(f'Error: {e}')
        return (False, False)
    finally:
        if gc_is_enabled:
            gc.enable()
        return (avg_sig_time/n_rounds, avg_ver_time/n_rounds)


if __name__ == '__main__':

    # Argument parsing from command-line
    parser = ArgumentParser()

    parser.add_argument(
        '--cipher',
        '-c',
        type=str,
        help='Cipher algorithm and mode of operation (AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-CCM, AES-GCM, AES-EAX, AES-SIV, AES-OCB, CHACHA20, SALSA20, RSA-OAEP). AES-ALL can be passed to test and compare all modes of operation on AES. SYMMETRIC-ALL can be passed to test and compare all symmetric cipher algorithms.',
        required = False,
    )

    parser.add_argument(
        '--hash',
        type=str,
        help='Hash algorithm (SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512). HASH-ALL can be passed to test and compare all hash algorithms.',
        required = False,
    )

    parser.add_argument(
        '--signature',
        '-s',
        type=str,
        help='Signature scheme (RSA-PSS, ECDSA, EdDSA). SIGN-ALL can be passed to test and compare all signature schemes',
        required = False,
    )

    parser.add_argument(
        '--key_length',
        '-k',
        type=int,
        action='store',
        help='Key length in bits (must be a multiple of 8, default: 256)',
    )

    parser.add_argument(
        '--data_size',
        '-d',
        type=str,
        action='store',
        default='1KB',
        help='Data size in B, KB or MB (e.g. 10MB, default: 1KB)',
    )

    parser.add_argument(
        '--rounds',
        '-r',
        type=int,
        action='store',
        default=1000,
        help='Number of encryption and decryption rounds to be computed (default: 1000)',
    )

    parser.add_argument(
        '--unit',
        '-u',
        type=str,
        action='store',
        default='ms',
        help='Time unit (ns, us, ms or s, default: ms)',
    )

    args = vars(parser.parse_args())

    hash_algo = args['hash']
    cipher = args['cipher']
    signature = args['signature']

    if not hash_algo and not cipher and not signature:
        print('A hash, cipher or signature algorithm must be provided')
        exit()
    elif hash_algo:
        hash_algo = hash_algo.upper()
        if hash_algo.startswith('SHA2-'):
            hash_algo = f'SHA-{hash_algo[5:]}'
    elif cipher:
        cipher = cipher.upper()
        if cipher == 'RSA':
            cipher = 'RSA-OAEP'
    elif signature:
        signature = signature.upper()
        if signature == 'RSA':
            signature = 'RSA-PSS'

    key_len = args['key_length']
    if (not key_len) and (cipher == 'RSA-OAEP' or signature == 'RSA-PSS'):
        key_len = 2048
    elif not key_len:
        key_len = 256
    if (key_len % 8) != 0:
        print('Key length must be a multiple of 8')
        exit()
    else:
        key_len_b = int(key_len / 8)

    data_size = args['data_size']
    m = search('([0-9]+)((M|K)?B)$', data_size)
    if not m:
        print('Data size in not in the right format (e.g. 10MB)')
        exit()
    data_len = int(m.group(1))
    if data_len == 0:
        print('Data size is not in the right format (e.g. 10MB)')
        exit()
    data_unit = m.group(2)
    if data_unit == 'KB':
        data_len *= 1024
    elif data_unit == 'MB':
        data_len *= 1024 * 1024

    n_rounds = args['rounds']
    if n_rounds < 1:
        print('Number of rounds must be greater or equal to 1')
        exit()

    unit = args['unit']
    if unit != 'ns' and unit != 'us' and unit != 'ms' and unit != 's':
        print(f'{unit} is not a supported time unit (use ns, us, ms or s)')
        exit()

    key = urandom(key_len_b)
    data = urandom(data_len)          

    # Check if Garbage Collector was initially enabled
    gc_is_enabled = gc.isenabled()

    # Adapt result according to unit
    unit_mul = 1000
    match unit:
        case 'ns':
            unit_mul = 1000000000
        case 'us':
            unit_mul = 1000000
        case 'ms':
            unit_mul = 1000
        case 's':
            unit_mul = 1

    # Compute algorithms and measure speed
    if hash_algo:
        match hash_algo:
            case 'SHA-224':
                avg_hash_time = sha_224(gc_is_enabled, data, n_rounds)
            case 'SHA-256':
                avg_hash_time = sha_256(gc_is_enabled, data, n_rounds)
            case 'SHA-384':
                avg_hash_time = sha_384(gc_is_enabled, data, n_rounds)
            case 'SHA-512':
                avg_hash_time = sha_512(gc_is_enabled, data, n_rounds)
            case 'SHA3-224':
                avg_hash_time = sha3_224(gc_is_enabled, data, n_rounds)
            case 'SHA3-256':
                avg_hash_time = sha3_256(gc_is_enabled, data, n_rounds)
            case 'SHA3-384':
                avg_hash_time = sha3_384(gc_is_enabled, data, n_rounds)
            case 'SHA3-512':
                avg_hash_time = sha3_512(gc_is_enabled, data, n_rounds)
            case 'HASH-ALL':
                hash_times = {}
                hash_algorithms = ['SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512']
                for hash_algorithm in hash_algorithms:
                    f = hash_algorithm.replace('-', '_').replace('/', '_').lower()
                    avg_hash_time = eval(f'{f}({gc_is_enabled}, {data}, {n_rounds})')
                    avg_hash_time = round(avg_hash_time * unit_mul, 3)
                    if hash_algorithm.startswith('SHA-'):
                        hash_algorithm = f'SHA2-{hash_algorithm[4:]}'
                    hash_times[hash_algorithm] = avg_hash_time
                hash_times = dict(sorted(hash_times.items(), key=lambda item: item[1]))
            case _:
                print(f'{hash_algo} is not a supported hash algorithm')
                exit()
        
        # Print results
        if (hash_algo == 'HASH-ALL'):
            print('Hash speed ranking:')
            best_time = list(hash_times.items())[0][1]
            n = 1
            for mode, time in hash_times.items():
                print(f'{n} - {mode} - {time}{unit} (+{round(time - best_time, 3)}{unit})')
                n += 1
        else:
            if not avg_hash_time:
                exit()
            else:
                hash_times  = round(avg_hash_time * unit_mul, 3)
                print(f'Hash time: {hash_times}{unit}')
    
    # Compute cipher algorithms and measure speed
    if cipher:
        match cipher:
            case 'AES-ECB':
                (avg_enc_time, avg_dec_time) = aes_ecb(gc_is_enabled, key, data, n_rounds)
            case 'AES-CBC':
                (avg_enc_time, avg_dec_time) = aes_cbc(gc_is_enabled, key, data, n_rounds)
            case 'AES-CFB':
                (avg_enc_time, avg_dec_time) = aes_cfb(gc_is_enabled, key, data, n_rounds)
            case 'AES-OFB':
                (avg_enc_time, avg_dec_time) = aes_ofb(gc_is_enabled, key, data, n_rounds)
            case 'AES-CTR':
                (avg_enc_time, avg_dec_time) = aes_ctr(gc_is_enabled, key, data, n_rounds)
            case 'AES-CCM':
                (avg_enc_time, avg_dec_time) = aes_ccm(gc_is_enabled, key, data, n_rounds)
            case 'AES-GCM':
                (avg_enc_time, avg_dec_time) = aes_gcm(gc_is_enabled, key, data, n_rounds)
            case 'AES-EAX':
                (avg_enc_time, avg_dec_time) = aes_eax(gc_is_enabled, key, data, n_rounds)
            case 'AES-SIV':
                (avg_enc_time, avg_dec_time) = aes_siv(gc_is_enabled, key, data, n_rounds)
            case 'AES-OCB':
                (avg_enc_time, avg_dec_time) = aes_ocb(gc_is_enabled, key, data, n_rounds)
            case 'RSA-OAEP':
                (avg_enc_time, avg_dec_time) = rsa_oaep(gc_is_enabled, key_len, data, n_rounds)
            case 'CHACHA20':
                (avg_enc_time, avg_dec_time) = chacha20(gc_is_enabled, key, data, n_rounds)
            case 'SALSA20':
                (avg_enc_time, avg_dec_time) = salsa20(gc_is_enabled, key, data, n_rounds)
            case 'AES-ALL':
                encryption_times = {}
                decryption_times = {}
                aes_modes = ['AES-ECB', 'AES-CBC', 'AES-CFB', 'AES-OFB', 'AES-CTR', 'AES-CCM', 'AES-GCM', 'AES-EAX', 'AES-SIV', 'AES-OCB']
                for aes_mode in aes_modes:
                    f = aes_mode.replace('-', '_').lower()
                    (avg_enc_time, avg_dec_time) = eval(f'{f}({gc_is_enabled}, {key}, {data}, {n_rounds})')
                    avg_enc_time = round(avg_enc_time * unit_mul, 3)
                    avg_dec_time = round(avg_dec_time * unit_mul, 3)
                    encryption_times[aes_mode] = avg_enc_time
                    decryption_times[aes_mode] = avg_dec_time
                encryption_times = dict(sorted(encryption_times.items(), key=lambda item: item[1]))
                decryption_times = dict(sorted(decryption_times.items(), key=lambda item: item[1]))
            case 'SYMMETRIC-ALL':
                if key_len != 256:
                    print('Key length must be equal to 256')
                    exit()
                encryption_times = {}
                decryption_times = {}
                ciphers = ['AES-ECB', 'AES-CBC', 'AES-CFB', 'AES-OFB', 'AES-CTR', 'AES-CCM', 'AES-GCM', 'AES-EAX', 'AES-SIV', 'AES-OCB', 'CHACHA20', 'SALSA20']
                for sym_cipher in ciphers:
                    f = sym_cipher.replace('-', '_').lower()
                    (avg_enc_time, avg_dec_time) = eval(f'{f}({gc_is_enabled}, {key}, {data}, {n_rounds})')
                    avg_enc_time = round(avg_enc_time * unit_mul, 3)
                    avg_dec_time = round(avg_dec_time * unit_mul, 3)
                    encryption_times[sym_cipher] = avg_enc_time
                    decryption_times[sym_cipher] = avg_dec_time
                encryption_times = dict(sorted(encryption_times.items(), key=lambda item: item[1]))
                decryption_times = dict(sorted(decryption_times.items(), key=lambda item: item[1]))
            case _:
                print(f'{cipher} is not a supported cipher algorithm and mode of operation')
                exit()
    
        # Print results
        if (cipher == 'AES-ALL') or (cipher == 'SYMMETRIC-ALL'):
            print('Encryption speed ranking:')
            best_time = list(encryption_times.items())[0][1]
            n = 1
            for mode, time in encryption_times.items():
                print(f'{n} - {mode} - {time}{unit} (+{round(time - best_time, 3)}{unit})')
                n += 1
            print('Decryption speed ranking:')
            best_time = list(decryption_times.items())[0][1]
            n = 1
            for mode, time in decryption_times.items():
                print(f'{n} - {mode} - {time}{unit} (+{round(time - best_time, 3)}{unit})')
                n += 1
        else:
            if False in (avg_enc_time, avg_dec_time):
                exit()
            else:
                avg_enc_time = round(avg_enc_time * unit_mul, 3)
                avg_dec_time = round(avg_dec_time * unit_mul, 3)
                print(f'Encryption time: {avg_enc_time}{unit}')
                print(f'Decryption time: {avg_dec_time}{unit}')

    if signature:
        match signature:
            case 'RSA-PSS':
                (avg_sig_time, avg_ver_time) = rsa_pss(gc_is_enabled, key_len, data, n_rounds)
            case 'ECDSA':
                (avg_sig_time, avg_ver_time) = ecdsa_256(gc_is_enabled, data, n_rounds)
            case 'EDDSA':
                (avg_sig_time, avg_ver_time) = eddsa_256(gc_is_enabled, data, n_rounds)
            case 'SIGN-ALL':
                signature_times = {}
                verification_times = {}
                schemes = ['RSA-PSS', 'ECDSA', 'EdDSA']
                for scheme in schemes:
                    f = scheme.replace('-', '_').lower()
                    if f.startswith('ec') or f.startswith('ed'):
                        f = f'{f}_256'
                        (avg_sig_time, avg_ver_time) = eval(f'{f}({gc_is_enabled}, {data}, {n_rounds})')
                    else:
                        (avg_sig_time, avg_ver_time) = eval(f'{f}({gc_is_enabled}, {key_len}, {data}, {n_rounds})')
                    avg_sig_time = round(avg_sig_time * unit_mul, 3)
                    avg_ver_time = round(avg_ver_time * unit_mul, 3)
                    signature_times[scheme] = avg_sig_time
                    verification_times[scheme] = avg_ver_time
                signature_times = dict(sorted(signature_times.items(), key=lambda item: item[1]))
                verification_times = dict(sorted(verification_times.items(), key=lambda item: item[1]))
            case _:
                print(f'{signature} is not a supported signature scheme')
                exit()

        # Print results
        if (signature == 'SIGN-ALL'):
            print('Signature speed ranking:')
            best_time = list(signature_times.items())[0][1]
            n = 1
            for mode, time in signature_times.items():
                print(f'{n} - {mode} - {time}{unit} (+{round(time - best_time, 3)}{unit})')
                n += 1
            print('Verification speed ranking:')
            best_time = list(verification_times.items())[0][1]
            n = 1
            for mode, time in verification_times.items():
                print(f'{n} - {mode} - {time}{unit} (+{round(time - best_time, 3)}{unit})')
                n += 1
        else:
            if False in (avg_sig_time, avg_ver_time):
                exit()
            else:
                avg_sig_time = round(avg_sig_time * unit_mul, 3)
                avg_ver_time = round(avg_ver_time * unit_mul, 3)
                print(f'Signature time: {avg_sig_time}{unit}')
                print(f'Verification time: {avg_ver_time}{unit}')