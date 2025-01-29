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

______________________________________________________________________________________________________________________________________________________________________________________
NEW VERSION
_______________________________________________________________________________________________________________________________________________________________________________________

import math

# Given RSA parameters
p = 163157151149139137
q = 115578717622022981

# Compute n and Euler's totient function φ(n)
n = p * q
f = (p - 1) * (q - 1)  # φ(n)
e = 65537  # Public key

# Ensure e and φ(n) are coprime
print("GCD(f, e):", math.gcd(f, e))  # Should be 1 for RSA to work

# Compute d using the modular inverse calculation d*e(mod(f)=1
d = pow(e, -1, f)  # d=(e^-1)(mod(f))

print(f'The value of d is {d}')

# Sample message to encrypt
sample = 12345

# Encryption function
def encrypt(plain_text, public_key, modulus):
    return pow(plain_text, public_key, modulus)

# Decryption function
def decrypt(encrypted_message, private_key, modulus):
    return pow(encrypted_message, private_key, modulus)

# Encrypt and decrypt the sample message
enc_m = encrypt(sample, e, n)
dec_m = decrypt(enc_m, d, n)

print("Encrypted message:", enc_m)
print("Decrypted message:", dec_m)  
