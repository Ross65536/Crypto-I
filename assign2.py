import sys
from lib import unhex, xor_bytestrings, hexify, add_bytestrings
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

# counts num blocks, +1 if last block not multiple of block size
def count_blocks(text):
  return int(len(text) / BLOCK_SIZE + 0.5 )

def skip_bytes(text, num_bytes):
  length = len(text)
  return text[num_bytes : length]

def generate_blocks(text):
  num_blocks = count_blocks(text)
  length = len(text)

  for i in range(0, num_blocks):
    start = i * BLOCK_SIZE
    end = (i+1) * BLOCK_SIZE
    if (end > length):
      end = length
    block = text[start : end]

    yield (i, block)


def decrypt_aes_cbc(key, ciphertext):
  if (len(ciphertext) % BLOCK_SIZE != 0):
    raise Exception("Not block aligned")

  if (len(ciphertext) // BLOCK_SIZE < 2):
    raise Exception("Invalid size")

  cipher = AESCipher(key)
  plaintext = b""
  dec_xor = ciphertext[0:BLOCK_SIZE] # IV
  for (i, ciphertext_block) in generate_blocks(skip_bytes(ciphertext, BLOCK_SIZE)):
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
  for (i, plaintext_block) in generate_blocks(padded_plaintext):
    xord = xor_bytestrings(plaintext_block, pre_xor)

    cipher_block = cipher.encrypt(xord)
    ciphertext += cipher_block
    pre_xor = cipher_block

  return iv + ciphertext

def int_to_bytes(num, num_bytes):
  return (num).to_bytes(num_bytes, byteorder='big')

def decrypt_aes_ctr(key, ciphertext):
  if (len(ciphertext) < BLOCK_SIZE):
    raise Exception("Invalid size")

  nonce_size = BLOCK_SIZE // 2
  nonce = ciphertext[0:BLOCK_SIZE]
  cipher = AESCipher(key)
  plaintext = b""

  for (i, cipher_block) in generate_blocks(skip_bytes(ciphertext, BLOCK_SIZE)):
    pre_enc = add_bytestrings(nonce, int_to_bytes(i, BLOCK_SIZE))
    enc = cipher.encrypt(pre_enc)

    plaintext_block = xor_bytestrings(enc, cipher_block)
    plaintext += plaintext_block

  return plaintext


#### ASSIGNMENT 2

def check_test(prefix, key_hex, cipher_hex, encryptor, decryptor):
  key1_bin = unhex(key_hex)
  cipher1_bin = unhex(cipher_hex)

  plaintext1 = decryptor(key1_bin, cipher1_bin)
  plaintexted1 = decryptor(key1_bin, encryptor(key1_bin, plaintext1))
  print(prefix + ": decrypt |{}| decrypt-encrypt-decrypt: |{}|".format(plaintext1.decode("utf-8"), plaintexted1.decode("utf-8")))


check_test("txt1", "140b41b22a29beb4061bda66b6747e14", "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", encrypt_aes_cbc, decrypt_aes_cbc)

plain = decrypt_aes_ctr(unhex("36f18357be4dbd77f050515c73fcf9f2"), unhex("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"))
print(plain.decode("utf-8"))