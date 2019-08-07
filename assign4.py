from urllib.parse import quote
from urllib.request import Request, urlopen, HTTPError
import sys
from lib import *
from enum import Enum

BLOCK_SIZE = 16

CIPHER_HEX = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4"

Requests = Enum('Requests', 'ok, padd_err mac_err')
TARGET = 'http://crypto-class.appspot.com/po?er='
def check_request_padding(ciphertext_hex):
  target = TARGET + quote(ciphertext_hex)    # Create query URL
  req = Request(target)         # Send HTTP request to server
  try:
      f = urlopen(req)          # Wait for response
      return Requests.ok
  except HTTPError as e:          
      # print("We got: %d" % e.code)       # Print response code
      if e.code == 404:
        return Requests.mac_err # bad padding
      elif e.code == 403:
        return Requests.padd_err # good padding
      else:
        raise Exception("Unexpected status received: " + e.code)


def cbc_aes_oracle_attack(ciphertext):
  if (len(ciphertext) % BLOCK_SIZE != 0):
    raise Exception("Not block aligned")

  if (len(ciphertext) // BLOCK_SIZE < 2):
    raise Exception("Invalid size")
  
  cipher_list = list(ciphertext)
  plaintext = []
  num_blocks = len(ciphertext) // BLOCK_SIZE
  for b in range(num_blocks - 1 - 1, -1, -1): # start at second to last
    cipher_store = cipher_list.copy()
    block_start = len(cipher_store) - 2 * BLOCK_SIZE
    for i in range(BLOCK_SIZE - 1, -1, -1):
      curr_index = block_start + i
      
      cipher_padded = cipher_store.copy()
      padding = BLOCK_SIZE - i
      for p in range(0, padding):
        cipher_padded[curr_index + p] ^= padding
      
      curr_char = cipher_padded[curr_index]
      for g in range(0, 256): # ASCII
        cipher_padded[curr_index] = curr_char ^ g
        
        hex = hexify(bytes(cipher_padded))
        req = check_request_padding(hex)

        is_padding_end = req == Requests.ok and g == padding and padding != 1 # won't work if padding is actually 1.
        # TODO figure out how to handle padding
        if (req == Requests.mac_err or is_padding_end ):
          plaintext.append(g)
          cipher_store[curr_index] ^= g
          print("found i={}: {} = {}".format(curr_index, g, chr(g)))
          break
      
        if (g == 255):
          raise Exception("Failed to guess")

    cipher_list = cipher_list[:-BLOCK_SIZE]
          
  return bytes(reversed(plaintext))

ciphertext = unhex(CIPHER_HEX)
plaintext = cbc_aes_oracle_attack(ciphertext)
print("Done!")
print(plaintext)  
