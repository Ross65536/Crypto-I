import binascii

def unhex(s):
   return binascii.unhexlify(s)

def hexify(bytestring):
  return binascii.hexlify(bytestring)

BYTE_LIMIT = 256

def add_bytestrings(s1, s2):
  carry = 0
  res = []
  pairs = [(a, b) for a, b in zip(s1, s2)]

  for a, b in reversed(pairs):
    add = a + b + carry
    r = add % BYTE_LIMIT 
    res.append(r)
    carry = add // BYTE_LIMIT # 0 or 1

  return bytes(reversed(res))


def xor_bytestrings(s1, s2):
  l = [ a ^ b for a, b in zip(s1, s2)]
  return bytes(l)

def count_blocks(text, block_size):
  return int(len(text) / block_size + 0.5 )

def skip_bytes(text, num_bytes):
  return text[num_bytes:]

def generate_blocks(text, block_size):
  num_blocks = count_blocks(text, block_size)
  length = len(text)

  for i in range(0, num_blocks):
    start = i * block_size
    end = (i+1) * block_size
    if (end > length):
      end = length
    block = text[start : end]

    yield (i, block)

# counts num blocks, +1 if last block not multiple of block size

