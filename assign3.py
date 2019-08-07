from lib import unhex, xor_bytestrings, hexify, add_bytestrings, count_blocks, skip_bytes, generate_blocks
from Crypto.Hash import SHA256

def read_file(name):
  in_file = open(name, "rb") # opening for [r]eading as [b]inary
  data = in_file.read() # if you only wanted to read 512 bytes, do .read(512)
  in_file.close()
  return data

BLOCK_SIZE = 1024

def sha256(msg):
  hash = SHA256.new()
  hash.update(msg)
  return hash.digest()

def sign_blocks(blocks):
  if (len(blocks) == 0):
    raise Exception("Invalid size")

  last_block = blocks[-1]
  signedblocks = [last_block]
  for block in reversed(blocks[:-1]):
    sha = sha256(last_block)
    pair = block + sha
    signedblocks.append(pair)
    last_block = pair

  last_sha = sha256(last_block)
  return (last_sha, reversed(signedblocks))

def check_blocks(sha, signedblocks):
  last_sha = sha
  for block in signedblocks:
    if last_sha != sha256(block):
      raise Exception("hash not matching")
    
    last_sha = block[BLOCK_SIZE:]


#### ASSIGNMENT 3

def test(filename):
  data = read_file(filename)
  blocks = [ x for (i, x) in generate_blocks(data, BLOCK_SIZE) ]
  (sha, blocks) = sign_blocks(blocks)
  sha_hex = hexify(sha)
  print(filename, ": ", sha_hex)
  check_blocks(sha, blocks)

test("test.mp4")
test("video.mp4")
