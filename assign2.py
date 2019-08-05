import sys
from lib import unhex, xor_bytestrings, hexify
from Crypto.Cipher.AES import AESCipher
from Crypto import Random 


BLOCK_SIZE = 16

KEY1 = "140b41b22a29beb4061bda66b6747e14"
CIPHER1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"

key1_bin = unhex(KEY1)
cipher1_bin = unhex(CIPHER1)

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

def decrypt_aes_cbc(key, ciphertext):
  if (len(ciphertext) % BLOCK_SIZE != 0):
    raise Exception("Invalid cipher")

  num_blocks = len(ciphertext) // BLOCK_SIZE
  if (num_blocks < 2):
    raise Exception("Invalid cipher")

  cipher = AESCipher(key)
  plaintext = b""
  dec_xor = ciphertext[0:BLOCK_SIZE] # IV
  for i in range(1, num_blocks):
    ciphertext_block = ciphertext[i * BLOCK_SIZE : (i+1) * BLOCK_SIZE]
    ll = len(ciphertext_block)
    decrypted_block = cipher.decrypt(ciphertext_block)

    plaintext_block = xor_bytestrings(dec_xor, decrypted_block)
    plaintext += plaintext_block

    dec_xor = ciphertext_block

  return unpad_pkcs7(plaintext)



def encrypt_aes_cbc(key, plaintext):
  padded_plaintext = pad_pkcs7(plaintext)

  num_blocks = len(padded_plaintext) // BLOCK_SIZE
  cipher = AESCipher(key)
  iv = Random.new().read(BLOCK_SIZE)
  pre_xor = iv

  ciphertext = b""
  for i in range(0, num_blocks):
    plaintext_block = padded_plaintext[i * BLOCK_SIZE : (i+1) * BLOCK_SIZE]
    xord = xor_bytestrings(plaintext_block, pre_xor)

    cipher_block = cipher.encrypt(xord)
    ciphertext += cipher_block
    pre_xor = cipher_block

  return iv + ciphertext

plaintext1 = decrypt_aes_cbc(key1_bin, cipher1_bin)
plaintexted1 =decrypt_aes_cbc(key1_bin, encrypt_aes_cbc(key1_bin, plaintext1))
print("plaintext1: decrypt |{}| encrypt-decrypt: |{}|".format(plaintext1.decode("utf-8"), plaintexted1.decode("utf-8")))