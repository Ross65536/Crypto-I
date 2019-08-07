import sys
from lib import unhex, xor_bytestrings, hexify, add_bytestrings, count_blocks, skip_bytes, generate_blocks
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



def decrypt_aes_cbc(key, ciphertext):
  if (len(ciphertext) % BLOCK_SIZE != 0):
    raise Exception("Not block aligned")

  if (len(ciphertext) // BLOCK_SIZE < 2):
    raise Exception("Invalid size")

  cipher = AESCipher(key)
  plaintext = b""
  dec_xor = ciphertext[0:BLOCK_SIZE] # IV
  for (i, ciphertext_block) in generate_blocks(skip_bytes(ciphertext, BLOCK_SIZE), BLOCK_SIZE):
    decrypted_block = cipher.decrypt(ciphertext_block)

    plaintext_block = xor_bytestrings(dec_xor, decrypted_block)
    plaintext += plaintext_block

    dec_xor = ciphertext_block

  return unpad_pkcs7(plaintext)

def cryptorandom(num_bytes):
  return Random.new().read(num_bytes)

def encrypt_aes_cbc(key, plaintext):
  padded_plaintext = pad_pkcs7(plaintext)

  cipher = AESCipher(key)
  iv = cryptorandom(BLOCK_SIZE)
  pre_xor = iv

  ciphertext = b""
  for (i, plaintext_block) in generate_blocks(padded_plaintext, BLOCK_SIZE):
    xord = xor_bytestrings(plaintext_block, pre_xor)

    cipher_block = cipher.encrypt(xord)
    ciphertext += cipher_block
    pre_xor = cipher_block

  return iv + ciphertext

def int_to_bytes(num, num_bytes):
  return (num).to_bytes(num_bytes, byteorder='big')

def apply_aes_ctr(key, nonce, source):
  cipher = AESCipher(key)
  dest = b""

  for (i, cipher_block) in generate_blocks(source, BLOCK_SIZE):
    pre_enc = add_bytestrings(nonce, int_to_bytes(i, BLOCK_SIZE))
    enc = cipher.encrypt(pre_enc)

    dest_block = xor_bytestrings(enc, cipher_block)
    dest += dest_block

  return dest

def decrypt_aes_ctr(key, ciphertext):
  if (len(ciphertext) < BLOCK_SIZE):
    raise Exception("Invalid size")

  nonce = ciphertext[0:BLOCK_SIZE]
  return apply_aes_ctr(key, nonce, skip_bytes(ciphertext, BLOCK_SIZE))

def encrypt_aes_ctr(key, plaintext):
  nonce = cryptorandom(BLOCK_SIZE)
  return nonce + apply_aes_ctr(key, nonce, plaintext)

#### ASSIGNMENT 2

def check_test(prefix, key_hex, cipher_hex, encryptor, decryptor):
  key1_bin = unhex(key_hex)
  cipher1_bin = unhex(cipher_hex)

  plaintext1 = decryptor(key1_bin, cipher1_bin)
  plaintexted1 = decryptor(key1_bin, encryptor(key1_bin, plaintext1))
  print(prefix + ": decrypt |{}| decrypt-encrypt-decrypt: |{}|".format(plaintext1.decode("utf-8"), plaintexted1.decode("utf-8")))


check_test("txt1", "140b41b22a29beb4061bda66b6747e14", "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", encrypt_aes_cbc, decrypt_aes_cbc)
check_test("txt1", "140b41b22a29beb4061bda66b6747e14", "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253", encrypt_aes_cbc, decrypt_aes_cbc)


check_test("ctr1", "36f18357be4dbd77f050515c73fcf9f2", "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329", encrypt_aes_ctr, decrypt_aes_ctr)
check_test("ctr1", "36f18357be4dbd77f050515c73fcf9f2", "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451", encrypt_aes_ctr, decrypt_aes_ctr)
