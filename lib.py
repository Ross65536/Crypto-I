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