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
import random

# TWO RSA primes
p = 163157151149139137
q = 115578717622022981

# Compute n and Euler's totient function φ(n)
n = p*q
f = (p-1)*(q-1) # φ(n)

# Function to find a valid public exponent e
def find_e(f):
    while True:
        e = random.randrange(3, f, 2)  # Pick a random odd number (avoids even factors)
        if math.gcd(e, f) == 1:  # Check if  coprime
            return e  

e = find_e(f)
print(f"Chosen public key e: {e}")


# Compute d using the modular inverse calculation d*e(mod(f)=1
d = pow(e, -1, f)  # d=(e^-1)(mod(f))

print(f'The value of d: {d}')

# Sample message to encrypt
message = 400
print(f'message: {message}')


# Encrypt and decrypt the message
enc_m = pow(message, e, n)
dec_m = pow(enc_m, d, n)

print("Encrypted message:", enc_m)
print("Decrypted message:", dec_m)  
