from aesencrypt import *
from aesdecrypt import *
import os
import numpy as np

KEY_SIZE = 128  #in bits
BLOCK_SIZE = 128  #in bits

aes_sbox = [
    [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16), int(
        '30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
    [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16), int(
        'ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
    [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16), int(
        '34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
    [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16), int(
        '07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
    [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16), int(
        '52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
    [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16), int(
        '6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
    [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16), int(
        '45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
    [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16), int(
        'bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
    [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16), int(
        'c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
    [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16), int(
        '46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
    [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16), int(
        'c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
    [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16), int(
        '6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
    [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16), int(
        'e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
    [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16), int(
        '61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
    [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16), int(
        '9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
    [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16), int(
        '41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]
]

rev_sbox = [
    [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16), int('38', 16), int(
        'bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16), int('fb', 16)],
    [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16), int('87', 16), int(
        '34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16), int('cb', 16)],
    [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16), int('3d', 16), int(
        'ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16), int('4e', 16)],
    [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16), int('b2', 16), int(
        '76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16), int('25', 16)],
    [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16), int('16', 16), int(
        'd4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16), int('92', 16)],
    [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16), int('da', 16), int(
        '5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16), int('84', 16)],
    [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16), int('0a', 16), int(
        'f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16), int('06', 16)],
    [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16), int('02', 16), int(
        'c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16), int('6b', 16)],
    [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16), int('ea', 16), int(
        '97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16), int('73', 16)],
    [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16), int('85', 16), int(
        'e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16), int('6e', 16)],
    [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16), int('89', 16), int(
        '6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16), int('1b', 16)],
    [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16), int('20', 16), int(
        '9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16), int('f4', 16)],
    [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16), int('31', 16), int(
        'b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16), int('5f', 16)],
    [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16), int('0d', 16), int(
        '2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16), int('ef', 16)],
    [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16), int('b0', 16), int(
        'c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16), int('61', 16)],
    [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16), int('26', 16), int(
        'e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16), int('7d', 16)]
]

def lookup(byte):
    x = byte >> 4
    y = byte & 15
    return aes_sbox[x][y]

def reverse_lookup(byte):
    x = byte >> 4
    y = byte & 15
    return rev_sbox[x][y]

def rotWord(key_box):
   dup_box = key_box.copy()
   temp = dup_box[3][3] #storing the first byte of w4
   for i in range(4):
      temp2 = dup_box[i][3]
      dup_box[i][3] = temp
      temp = temp2
   return dup_box

def subWord(key_box):
   dup_box = key_box.copy()
   for i in range(4):
      dup_box[i][3] = lookup(dup_box[i][3])
   return dup_box

def rCon(key_box,round):
   dup_box = key_box.copy()
   rcon = [[1, 0, 0, 0]]
   for i in range(1, 12):
      first_byte = rcon[i-1][0]*2
      rcon.append([first_byte, 0, 0, 0])
      if rcon[i-1][0] > 0x80:
         rcon[i-1][0] = rcon[i-1][0] ^ 0x11b
   dup_box[0][3] = dup_box[0][3]^rcon[round][0]
   return dup_box

def expandKey(key_byte):
   round_keys = []
   key_box = np.array(key_byte).reshape(4, 4)
   og_key = key_box.copy()
   prev_key = key_box.copy()
   round_keys.append(og_key)
   #Now generating round keys
   for i in range(10):
      if i == 0:
         prev_key = og_key.copy()
      else:
         prev_key = round_keys[i-1].copy()
      
      new_round_key = prev_key.copy()
      modp_key = rotWord(prev_key)
      modp_key = subWord(modp_key)
      modp_key = rCon(modp_key,i)
      for j in range(4):
         for k in range(4):
            if j == 0:
               new_round_key[k][0] = new_round_key[k][0]^modp_key[k][3]
            else:
               new_round_key[k][j] = new_round_key[k][j-1]^prev_key[k][j]
      round_keys.append(new_round_key)
   return round_keys

def processPT(pt_bytes,pt_hex):
    plaintext_size = len(pt_hex)*4
    num_blocks_req = int(plaintext_size/128) + 1
    if num_blocks_req == 1:
        padding_size = int((128-plaintext_size)/8)
        if padding_size == 0:
            padding_size = 16   #adding a dummy block
        padded_pt_bytes = padInPKCS(pt_bytes,padding_size)
        print(f'Plaintext (after padding) = {padded_pt_bytes.hex()}')
        boxed_pt_bytes = boxPTBytes(padded_pt_bytes)
        return num_blocks_req,boxed_pt_bytes
    else:
        padding_size = int(((num_blocks_req*128)-plaintext_size)/8)
        if padding_size == 0:
            padding_size = 16   #adding a dummy block
        padded_pt_bytes = padInPKCS(pt_bytes,padding_size)
        print(f'Plaintext (after padding) = {padded_pt_bytes.hex()}')
        pt_blocks = []
        for i in range(num_blocks_req):
            block_i = [padded_pt_bytes[j] for j in range(16*i,(i+1)*16)]
            boxed_pt_bytes = boxPTBytes(block_i)
            pt_blocks.append(boxed_pt_bytes)
        return num_blocks_req,pt_blocks
        
def padInPKCS(message_bytes,padding_size):
   return message_bytes + bytes([padding_size] * padding_size)

def unPadPKCS(decrypted_bytes):
    np_array = np.array(decrypted_bytes)
    flatten_array = np_array.ravel()
    last_byte = flatten_array[len(flatten_array)-1]
    unpadded_decrypted_bytes = flatten_array[:len(flatten_array) - int(last_byte)]
    decrypted_hex = ''.join(format(x, '02x') for x in unpadded_decrypted_bytes)
    return decrypted_hex

def boxPTBytes(pt_box):
   box_output = np.array(pt_box).reshape(4, 4)
   return box_output

#Random key acquired and processed
key_byte = bytearray(os.urandom(int(KEY_SIZE/8)))
key_hex = key_byte.hex()
print(f'\nRandom key (in Hexadecimal) = {key_hex} \n')
round_keys = expandKey(key_byte)

plaintext = input('Enter text you want to test AES on: ')
plaintext_byte = bytearray(plaintext,'utf-8')
plaintext_hex = plaintext_byte.hex()
print(f'\nPlaintext (in Hexadecimal) = {plaintext_hex}')
numblocks, pt_blocks = processPT(plaintext_byte,plaintext_hex)

if numblocks == 1:
    encrypted_bytes,encrypted_hex = encryptIt(pt_blocks,round_keys)
    print(f'\nCiphertext = {encrypted_hex}')
    decrypted_bytes,decrypted_hex = decryptIt(encrypted_bytes,round_keys)
    print(f'Decrypted (in Hexadecimal) = {decrypted_hex}')
    decrypted_hex = unPadPKCS(decrypted_bytes)
    print(f'Unpadded Decrypted (in Hexadecimal) = {decrypted_hex}')
    print(f'\nDecrypted text (in String) = {bytearray.fromhex(decrypted_hex).decode()}')
else:
    encrypted_hexstr = ''
    decrypted_hexstr = ''
    decrypted_bytearr = []
    for i in range(numblocks):
        encrypted_bytes,encrypted_hex = encryptIt(pt_blocks[i],round_keys)
        encrypted_hexstr = encrypted_hexstr+encrypted_hex
        decrypted_bytes,decrypted_hex = decryptIt(encrypted_bytes,round_keys)
        decrypted_hexstr = decrypted_hexstr+decrypted_hex
        np_array = np.array(decrypted_bytes)
        flatten_array = np_array.ravel()
        decrypted_bytearr.append(flatten_array)
    print(f'\nCiphertext = {encrypted_hexstr}')
    print(f'Decrypted (in Hexadecimal) = {decrypted_hexstr}')
    decrypted_hex = unPadPKCS(decrypted_bytearr)
    print(f'Unpadded Decrypted (in Hexadecimal) = {decrypted_hex}')
    print(f'\nDecrypted text (in String) = {bytearray.fromhex(decrypted_hex).decode()}')

    

