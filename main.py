import math

import random

# TWO RSA primes
p = 163157151149139137
q = 115578717622022981

# Compute n and Euler's totient function φ(n)
n = p * q
f = (p - 1) * (q - 1)  # φ(n)


# Function to find a valid public exponent e
def find_e(f):
    while True:
        e = random.randrange(3, f, 2)  # Pick a random odd number (avoids even factors)
        if math.gcd(e, f) == 1:  # Check if  coprime
            return e


e = find_e(f)
print(f"Chosen public key e: {e}")


# Compute d using the modular inverse calculation from d*e(mod(f))==1
d = pow(e, -1, f)  # d=(e^-1)(mod(f))

print(f"The value of d: {d}")


def encrypter(e, n, block_size=4):
    enc_m = []

    message = input("Please enter the message you want to encrypt: ")
    Ascii_values = [format(ord(c), "08b") for c in message]

    # adds null values (0) at the end of list to make it have correct amount of blocks
    while len(Ascii_values) % block_size != 0: 
        Ascii_values.append(format(0, "08b"))  # Padding with binary '0'


    full_ciphertext = ""
    for i in range(0, len(Ascii_values), block_size):
        block_to_encrypt_bytes = "".join(Ascii_values[i : i + block_size])

        print(block_to_encrypt_bytes)

        enc_w = pow(int(block_to_encrypt_bytes), e, n)
        full_encrypted_block_with_headers = ""
        enc_w_str = str(enc_w)
        full_encrypted_block_with_headers += str(len(enc_w_str))
        while len(enc_w_str) != 35:
            enc_w_str += "1"
        full_encrypted_block_with_headers += enc_w_str
        enc_m.append(full_encrypted_block_with_headers)

    return "".join(enc_m)


def find_block(encrypted_message):
    reached_end = False
    current_first_index = 0
    current_last_index = 0
    finished_len = 0
    current_last_index += 2

    current_block_true_size = int(
        encrypted_message[current_first_index:current_last_index]
    )
    current_block = encrypted_message[
        current_last_index : (current_block_true_size + current_last_index)
    ]
    if current_block_true_size != 35:
        filler_ends_index = current_block_true_size + 2 + (35 - current_block_true_size)
        return current_block, encrypted_message[filler_ends_index:]

    else:
        return current_block, encrypted_message[current_block_true_size + 2 :]


def decrypt(encrypted_message, private_key):

    plaintext = ""
    blocks = []
    decrypted_blocks = []
    other_blocks = ""
    block, leftover = find_block(encrypted_m)

    blocks.append(block)
    other_blocks = leftover

    print(len(leftover))
    while len(other_blocks) != 0:
        current_block, left_blocks = find_block(other_blocks)
        other_blocks = left_blocks
        blocks.append(current_block)

    for block in blocks:
        decrypted = pow(int(block), private_key, n)
        decrypted = str(decrypted)
        if len(decrypted) % 8 != 0:
            decrypted = f"0{decrypted}"
        print("decrypted: ", decrypted)
        for i in range(0, len(decrypted), 8):
            byte = decrypted[i : i + 8]
            binary_int = int(byte, 2)
            plaintext += chr(binary_int)
            print(f"byte: {byte} binary_int: {binary_int}")

    print(plaintext)
    print("current block", block)
    print(other_blocks)
    print("left overs", leftover)
    print(blocks)


encrypted_m = encrypter(e, n)
print("encrypted:", encrypted_m)

decrypt(encrypted_m, d)
# print("decrypt:", decrypt(encrypted_m, d))
