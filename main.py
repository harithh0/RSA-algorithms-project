import math

p = 163157151149139137
q = 115578717622022981


n = p * q
f = (p - 1) * (q - 1)
e = 3 
d = 218457
print((e * d) % f)
print(math.gcd(f,e))


sample = 12345


def encrypt(plain_text, public_key):
    encrypted = pow(plain_text, public_key, n)
    return encrypted


def decrypt(encrypted_message, private_key):
    decrypted = pow(encrypted_message, private_key, n)
    return decrypted


enc_m = encrypt(sample, e)
dec_m = decrypt(enc_m, d)

print(dec_m)
