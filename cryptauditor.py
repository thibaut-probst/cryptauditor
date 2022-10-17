from argparse import ArgumentParser
from os import urandom
from re import search
from time import perf_counter
import gc
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from binascii import hexlify

if __name__ == '__main__':

    # Argument parsing from command-line
    parser = ArgumentParser()

    parser.add_argument(
        '--cipher',
        '-c',
        type=str,
        help='Cipher algorithm and mode of operation (AES-ECB, AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-CCM, AES-GCM, AES-EAX, AES-SIV, AES-OCB, RSA-OAEP',
        required = True,
    )

    parser.add_argument(
        '--key_length',
        '-k',
        type=int,
        action='store',
        default=256,
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

    cipher = args['cipher']
    if cipher == 'RSA':
        cipher = 'RSA-OAEP'

    key_len = args['key_length']
    if (key_len % 8) != 0:
        print('Key length must be a multiple of 8')
        exit()
    else:
        key_len_b = int(key_len / 8)

    data_size = args['data_size']
    m = search('([0-9]+)((M|K)?B)$', data_size)
    if not m:
        print('Data size must be positive (e.g. 10MB)')
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

    match cipher:
        case 'AES-ECB':
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
                        print(f'Warning: decrypted ciphertext does not match initial plaintext!')
                    avg_dec_time += end - start
            except Exception as e:
                print(f'Error: {e}')
                exit()
            finally:
                if gc_is_enabled:
                    gc.enable()
        case 'AES-CBC':
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
                        print(f'Warning: decrypted ciphertext does not match initial plaintext!')
                    avg_dec_time += end - start
            except Exception as e:
                print(f'Error: {e}')
                exit()
            finally:
                if gc_is_enabled:
                    gc.enable() 
        case 'AES-CFB':
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
                        print(f'Warning: decrypted ciphertext does not match initial plaintext!')
                    avg_dec_time += end - start
            except Exception as e:
                print(f'Error: {e}')
                exit()
            finally:
                if gc_is_enabled:
                    gc.enable() 
        case 'AES-OFB':
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
                        print(f'Warning: decrypted ciphertext does not match initial plaintext!')
                    avg_dec_time += end - start
            except Exception as e:
                print(f'Error: {e}')
                exit()
            finally:
                if gc_is_enabled:
                    gc.enable()
        case 'AES-CTR':
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
                        exit()
                    avg_dec_time += end - start
            except Exception as e:
                print(f'Error: {e}')
                exit()
            finally:
                if gc_is_enabled:
                    gc.enable()
        case 'AES-CCM':
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
                        exit()
                    avg_dec_time += end - start
            except Exception as e:
                print(f'Error: {e}')
                exit()
            finally:
                if gc_is_enabled:
                    gc.enable()
        case 'AES-GCM':
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
                        exit()
                    avg_dec_time += end - start
            except Exception as e:
                print(f'Error: {e}')
                exit()
            finally:
                if gc_is_enabled:
                    gc.enable()
        case 'AES-EAX':
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
                        exit()
                    avg_dec_time += end - start
            except Exception as e:
                print(f'Error: {e}')
                exit()
            finally:
                if gc_is_enabled:
                    gc.enable()
        case 'AES-SIV':
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
                        exit()
                    avg_dec_time += end - start
            except Exception as e:
                print(f'Error: {e}')
                exit()
            finally:
                if gc_is_enabled:
                    gc.enable()
        case 'AES-OCB':
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
                        exit()
                    avg_dec_time += end - start
            except Exception as e:
                print(f'Error: {e}')
                exit()
            finally:
                if gc_is_enabled:
                    gc.enable()
        case 'RSA-OAEP':
            if key_len < 1024:
                print(f'RSA key length must be greater than 1024')
                exit()
            elif data_len > ( key_len / 8 - 42 ):
                print(f'Plaintext data size must be less or equal than {int(key_len / 8 - 42)}B (RSA key length minus 42-byte OAEP padding data)')
                exit()
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
                        exit()
                    avg_dec_time += end - start

            finally:
                if gc_is_enabled:
                    gc.enable()
        case _:
            print(f'{cipher} is not a supported cipher algorithm and mode of operation')
            exit()

    # Adapt result according to unit
    match unit:
        case 'ns':
            avg_enc_time = round(avg_enc_time * 1000000000 / n_rounds, 3)
            avg_dec_time = round(avg_dec_time * 1000000000 / n_rounds, 3)
        case 'us':
            avg_enc_time = round(avg_enc_time * 1000000 / n_rounds, 3)
            avg_dec_time = round(avg_dec_time * 1000000 / n_rounds, 3)
        case 'ms':
            avg_enc_time = round(avg_enc_time * 1000 / n_rounds, 3)
            avg_dec_time = round(avg_dec_time * 1000 / n_rounds, 3)
        case 's':
            avg_enc_time = round(avg_enc_time / n_rounds, 3)
            avg_dec_time = round(avg_dec_time / n_rounds, 3)
    
    # Print results
    print(f'Encryption time: {avg_enc_time}{unit}')
    print(f'Decryption time: {avg_dec_time}{unit}')