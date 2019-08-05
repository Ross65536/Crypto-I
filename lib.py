import binascii

def unhex(s):
   return binascii.unhexlify(s)

def hexify(bytestring):
  return binascii.hexlify(bytestring)

def xor_bytestrings(s1, s2):
  if (len(s1) != len(s2)):
    raise Exception("different size")

  l = [ a ^ b for a, b in zip(s1, s2)]
  return bytes(l)