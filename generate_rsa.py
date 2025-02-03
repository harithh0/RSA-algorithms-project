import math
import random

# TWO RSA primes
P_VALUE = 163157151149139137
Q_VALUE = 115578717622022981


# Function to find a valid public exponent e
def find_e(f):
    while True:
        e = random.randrange(3, f, 2)  # Pick a random odd number (avoids even factors)
        if math.gcd(e, f) == 1:  # Check if  coprime
            return e


def generate_rsa():

    # Compute n and Euler's totient function φ(n)
    n_value = P_VALUE * Q_VALUE
    f_value = (P_VALUE - 1) * (Q_VALUE - 1)  # φ(n)

    public_key = find_e(f_value)
    # Compute d using the modular inverse calculation from d*e(mod(f))==1
    private_key = pow(public_key, -1, f_value)  # d=(e^-1)(mod(f))

    # print(f"Chosen public key e: {public_key}")
    # print(f"The value of d: {d}")
    return (public_key, private_key, n_value)


if __name__ == "__main__":
    public_key, private_key, n_value = generate_rsa()
    print(f"Public Key (e, n): ({public_key}, {n_value})")
    print(f"Private Key (d, n): ({private_key}, {n_value})")