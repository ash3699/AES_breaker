from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aesLongKeyGen24 import *
import time

# Function to read from a text file and append the lines in a list
def read_file(text_path):
    lines = []
    f = open(text_path,'r')
    for line in f:
        lines.append(line.rstrip())
    return lines

# Function takes in longkey and secrect cipher text anf returns the secret message
def get_secret_message(long_key, cipher_text):
    # converts hexadecimel to bytes
    byte_cipher_text = bytes.fromhex(cipher_text)
    IV=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    cipher_object = Cipher(algorithms.AES(long_key), modes.CBC(IV))
    decryptor_object = cipher_object.decryptor()
    specialPlainText=decryptor_object.update(byte_cipher_text)+ decryptor_object.finalize()
    
    return str(specialPlainText.decode())

# Function takes key in its integer value and returns the longkey and shortkey pair
def get_expanded_key(int_key):
    key_size_bytes = 3
    short_int_key = int_key << 4
    short_byte_key = short_int_key.to_bytes(key_size_bytes, byteorder= 'big')
    short_key = bytearray(short_byte_key)
    # Expand key to 128 bits
    key = expandKey(shortKey=short_key)
    return key, short_key

# Function takes in Candidate key and verifies it using other plaintext ciphertext pairs
def verify_candidate_key(key, IV, plain_text_list, cipher_text_list):
    key_check = False
    for i in range(1, len(plain_text_list)):
        key_check = check_candidate_key(key, IV, plain_text_list[i], cipher_text_list[i])
    return key_check

# Function takes in all possible keys and searches for a candidate key using a single pair of plaintext and ciphertext 
def check_candidate_key(key, IV, plain_text, cipher_text):
    cipher_text_object = Cipher(algorithms.AES(key), modes.CBC(IV))
    encryptor_object = cipher_text_object.encryptor() 
    cipher_by_AES = encryptor_object.update(plain_text.encode('UTF-8')) + encryptor_object.finalize()
    if cipher_by_AES.hex() == cipher_text:
        return True
    else:
        return False 

# Function generates all the possible 20 bit keys and checks for a valid key using brute force
def brute_force_break(plain_text_list, cipher_text_list):
    # Selecting the first plaintext ciphertext pair
    plain_text = plain_text_list[0]
    cipher_text = cipher_text_list[0]
    IV=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    for int_key in range(2**20):
        key, short_key = get_expanded_key(int_key)
        key_check = check_candidate_key(key, IV, plain_text, cipher_text)
        if key_check == True:
            candidate_key_check = verify_candidate_key(key, IV, plain_text_list, cipher_text_list)
            if candidate_key_check == True:
                return True, short_key, key       
    return False, short_key, key

# Function saves the secret message in the text file 'aesSecretMessage.txt'
def save_secret_message(secret_message):
    f = open("aesSecretMessage.txt","w")
    f.write(secret_message + "\n")
    f.close()
            
def main():
    print('Code is running. Please wait....')
    plain_text_path = 'aesPlaintexts.txt'
    plain_text_list = read_file(plain_text_path)
    cipher_text_path = 'aesCiphertexts.txt'
    cipher_text_list = read_file(cipher_text_path)
    start_time = time.time()
    got_key, short_key, long_key = brute_force_break(plain_text_list,cipher_text_list)

    if got_key == True:
        secret_message = get_secret_message(long_key, cipher_text_list[-1])
        end_time = time.time()
        print(f'The short key in hexadecimal: {str(short_key.hex())}')
        print(f'The long key in hexadecimal : {str(long_key.hex())}')
        print(f'The secret message is       : {secret_message}')
        print(f'Total time taken            : {str(end_time-start_time)}')
        save_secret_message(secret_message)
    else:
        print('No key was found')

if __name__ == '__main__':
    main()