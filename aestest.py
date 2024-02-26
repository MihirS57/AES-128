from aesencrypt import *
from aesdecrypt import *
import os

KEY_SIZE = 128  #in bits
BLOCK_SIZE = 128    #in bits

def padInPKCS(message_bytes,padding_size):
   return message_bytes + bytes([padding_size] * padding_size)

plaintext = input('Enter text you want to test AES on: ')
plaintext_bytes = plaintext.encode('utf-8')
plaintext_hex = plaintext_bytes.hex()
key_hex = os.urandom(int(KEY_SIZE/8)).hex()

plaintext_size = len(plaintext_hex)*4
padding_size = int((128-plaintext_size)/8)

padded_pt_bytes = padInPKCS(plaintext_bytes,padding_size)

print(f'Here is your plaintext in hexadecimal = {plaintext_hex}')
print(f'Length of your plaintext = {plaintext_size} bits, number of bytes to be padded = {padding_size}')
print(f'Plaintext after padding in hexadecimal = {padded_pt_bytes.hex()} \nAnd its length = {len(padded_pt_bytes.hex())*4}')
print(f'Here is the secret key = {key_hex}')
# displayThisInEncrypt(plaintext_hex)
# displayThisInDecrypt(plaintext_hex)
