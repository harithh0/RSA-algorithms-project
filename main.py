import math

p = 163157151149139137
q = 115578717622022981


n = p * q
f = (p - 1) * (q - 1)
e = 65537
d = 218457
print((e * d) % f)
print(d)
