import sys
from lib import unhex, xor_bytestrings, hexify
from Crypto.Cipher.AES import AESCipher
from Crypto import Random 


BLOCK_SIZE = 16

def unpad_pkcs7(plaintext):
  padding = plaintext[-1]
  plaintext_len = len(plaintext) - padding
  
  for i in range(plaintext_len, len(plaintext)):
    if (plaintext[i] != padding):
      raise Exception("Invalid padding")

  return plaintext[0:plaintext_len]

def pad_pkcs7(plaintext):
  modulo = len(plaintext) % BLOCK_SIZE
  padding = BLOCK_SIZE if modulo == 0 else BLOCK_SIZE - modulo

  for i in range(0, padding):
    plaintext += bytes([padding])

  return plaintext

def count_blocks(text, min_blocks = 0):
  if (len(text) % BLOCK_SIZE != 0):
    raise Exception("Not block aligned")

  num_blocks = len(text) // BLOCK_SIZE
  if (num_blocks < min_blocks):
    raise Exception("Invalid size")

  return num_blocks

def generate_blocks(text, start_block = 0):
  num_blocks = count_blocks(text, start_block)

  for i in range(start_block, num_blocks):
    yield text[i * BLOCK_SIZE : (i+1) * BLOCK_SIZE]


def decrypt_aes_cbc(key, ciphertext):
  count_blocks(ciphertext, 2)

  cipher = AESCipher(key)
  plaintext = b""
  dec_xor = ciphertext[0:BLOCK_SIZE] # IV
  for ciphertext_block in generate_blocks(ciphertext, 1):
    decrypted_block = cipher.decrypt(ciphertext_block)

    plaintext_block = xor_bytestrings(dec_xor, decrypted_block)
    plaintext += plaintext_block

    dec_xor = ciphertext_block

  return unpad_pkcs7(plaintext)

def encrypt_aes_cbc(key, plaintext):
  padded_plaintext = pad_pkcs7(plaintext)

  cipher = AESCipher(key)
  iv = Random.new().read(BLOCK_SIZE)
  pre_xor = iv

  ciphertext = b""
  for plaintext_block in generate_blocks(padded_plaintext):
    xord = xor_bytestrings(plaintext_block, pre_xor)

    cipher_block = cipher.encrypt(xord)
    ciphertext += cipher_block
    pre_xor = cipher_block

  return iv + ciphertext

#### ASSIGNMENT 2

def check_test(prefix, key_hex, cipher_hex, encryptor, decryptor):
  key1_bin = unhex(key_hex)
  cipher1_bin = unhex(cipher_hex)

  plaintext1 = decryptor(key1_bin, cipher1_bin)
  plaintexted1 = decryptor(key1_bin, encryptor(key1_bin, plaintext1))
  print(prefix + ": decrypt |{}| decrypt-encrypt-decrypt: |{}|".format(plaintext1.decode("utf-8"), plaintexted1.decode("utf-8")))


check_test("txt1", "140b41b22a29beb4061bda66b6747e14", "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", encrypt_aes_cbc, decrypt_aes_cbc)

