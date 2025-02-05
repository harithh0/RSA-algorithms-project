import math
import random

#  RSA primes
n1 = 100000000000000000
n2 = 155555555555555555
n3 = 199999999999999999


def pseudo_prime(n1, n2, k=10):
    # finds a pseudo-prime between n1 and n2 using Fermat's test.
    while True:
        p = random.randint(n1, n2)

        if p % 2 == 0:
            p += 1

        if fermat_test(p, k):
            return p


# fermat’s primality test
def fermat_test(p, k=10):
    if p < 2:
        return False
    for _ in range(k):
        a = random.randint(2, p - 1)
        if pow(a, p - 1, p) != 1:
            return False
    return True


# find pseudo-prime
p = pseudo_prime(n1, n2)
q = pseudo_prime(n2, n3)


# finds a valid public exponent e
def find_e(f):
    while True:
        e = random.randrange(3, f, 2)
        if math.gcd(e, f) == 1:
            return e


def extended_gcd(a, b):
    # returns gcd(a, b) and the coefficients x, y such that ax + by = gcd(a, b)
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi


def generate_rsa():

    # computes  n and Euler's totient function φ(n)
    n_value = p * q
    f = (p - 1) * (q - 1)  # φ(n)

    # find public exponent e using math.gcd function
    public_key = find_e(f)

    # computes  d using the modular inverse calculation from d*e(mod(f))==1
    private_key = mod_inverse(public_key, f)

    return (public_key, private_key, n_value)


if __name__ == "__main__":
    public_key, private_key, n_value = generate_rsa()
    print(f"Public Key (e, n): ({public_key}, {n_value})")
    print(f"Private Key (d, n): ({private_key}, {n_value})")
