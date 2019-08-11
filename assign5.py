from gmpy2 import mpz, invert, powmod, t_mod, mul, add
from collections import defaultdict

p = mpz('13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171')
g = mpz('11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568')
h = mpz('3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333')

B = 2**20

print("Building table")
hash_table = defaultdict(list)
# build table
for x1 in range(0, B+1):
  ginv = powmod(g, -x1, p)
  mult = mul(h, ginv)
  left_side = t_mod(mult, p)
  hashvalue = hash(left_side)

  hash_table[hashvalue] += [(left_side, x1)]

print("Table built")

g_pow_B = powmod(g, B, p) 
for x0 in range(0, B+1):
  right_side = powmod(g_pow_B, x0, p)
  hashvalue = hash(right_side)

  if (hashvalue in hash_table):
    for (left_side, x1) in hash_table[hashvalue]:
      if (left_side == right_side):
        print("Found value")
        x = mul(mpz(x0), B)
        x = add(x, mpz(x1))
        x = t_mod(x, p)
        print("x is: ", x)
        exit(0)

print("Not found")
