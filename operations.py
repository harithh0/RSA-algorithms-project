def encrypt_message(message, public_key, n_value, block_size=4):
    """
    encrypts user provided text/string

    returns encrypted message in string format: "hello world!" -> "10101s..." -> "29174194..."
    """

    error = 0
    enc_m = []
    while (
        error == 0
    ):  # allows user to reenter message instead of ending the program (can change if wanted)

        # turns each character into binary form with leading 1s if needed
        binary_values = []
        for c in message:
            ascii_to_binary_string = format(ord(c), "08b")
            if len(ascii_to_binary_string) > 8:  # special ascii character
                # A non-ascii character has been found as it is greater than 8 bits long
                # for now we will just replace it with a null value
                binary_values.append(format(0, "08b"))
            else:
                error = 1
                binary_values.append(ascii_to_binary_string)

    # adds null values (0) at the end of list to make it have correct amount of blocks if needed
    # each block must have 4 characters or 4 bytes (32 bits) if short then it will add 0s
    while len(binary_values) % block_size != 0:
        binary_values.append(format(0, "08b"))

    full_ciphertext = ""

    # goes through 0-to-length of the binary values list by 4
    # so in short it goes like this: we have [10s, 10s, 10s, 10s, 10s, 10s and so on...], each space repersenting the binary form of a character
    # we have exactly even amount divisible by 4
    for i in range(0, len(binary_values), block_size):
        # takes the 4 values and turns them into a complete string
        # ex: first binary characters will be turned from list format [10,10,10,10] -> 10101010 to combined string
        block_to_encrypt_bytes = "".join(binary_values[i : i + block_size])

        print(block_to_encrypt_bytes)

        # encrypts this binary string called enc_w
        enc_w = pow(int(block_to_encrypt_bytes), public_key, n_value)

        """
        - adds headers to the binary string such as length of encrypted binary string and a seperator which will be "1".
        - the sperator will seperate the encrypted blocks so that we are able to combine them together and later on tell where a specifc block
        begins and ends. The seperator will only be placed if the encrypted block is not 35 characters which was found to be the max.
        - the complete block will look something like this <len_of_encrypted_block_without_headers>ENCRYPTED_BLOCK<option_seperator>
        """
        full_encrypted_block_with_headers = ""
        enc_w_str = str(enc_w)
        full_encrypted_block_with_headers += str(len(enc_w_str))
        while len(enc_w_str) != 35:
            enc_w_str += "1"
        full_encrypted_block_with_headers += enc_w_str
        enc_m.append(full_encrypted_block_with_headers)

    # returns the fully encrypted message in string format
    return "".join(enc_m)


def find_block(encrypted_message):
    """
    finds the the specifc blocks within a fully encrypted message with multiple blocks

    identifies sperators and length of blocks to extract the headers from the encrypted block

    returns the block extracted and the the left-over blocks that need to be extracted from the complete message IF any
    """
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


def decrypt_message(encrypted_message, private_key, n_value, block_size=4):
    """
    decrypts complete encrypted message

    returns decrypted message
    """

    plaintext = ""
    blocks = []
    decrypted_blocks = []
    other_blocks = ""

    # initalizing the first block to be found and if there are any other blocks
    block, leftover = find_block(encrypted_message)
    blocks.append(block)
    other_blocks = leftover

    """
    - loops over while there are still blocks inside the complete encrypted message and extracts the encrypted block without the headers
    - it looks something like this:
        # comp|lete|_enc|rypt|ed_m|ess|age... -> |lete|_enc|rypt|ed_m|ess|age... -> |_enc|rypt|ed_m|ess|age... -> and so on.. until we get 
        through the whole message until there are no more blocks.
    """
    while len(other_blocks) > 1:
        current_block, left_blocks = find_block(other_blocks)
        other_blocks = left_blocks
        blocks.append(current_block)

    # after extracting all the blocks, we will loop to each block and decrypt it from ciphertext -> binary -> then change it to ascii
    for block in blocks:
        decrypted = pow(int(block), private_key, n_value)
        print("Decrypted before conversion: ", decrypted)
        decrypted = str(decrypted)
        if len(decrypted) % 8 != 0:
            decrypted = decrypted.zfill(32)
        print("decrypted: ", decrypted)
        for i in range(0, len(decrypted), 8):
            byte = decrypted[i : i + 8]
            binary_int = int(byte, 2)
            plaintext += chr(binary_int)
            print(f"byte: {byte} binary_int: {binary_int}")

    return plaintext


def convert_str_to_decmial(string):
    message_in_decmial = ""
    for c in string:
        message_in_decmial += format(ord(c))

    return int(message_in_decmial)


def sign_message(plaintext_message, private_key, n_value):

    message_in_decmial = convert_str_to_decmial(plaintext_message)

    # in real life, we would sign the hash of the message instead of the message itself
    # message_hash = hashlib.sha256(str(binary_to_decmial).encode()).hexdigest()
    # message_hash_int = int(message_hash, 16)

    message_signature = pow(message_in_decmial, private_key, n_value)
    return message_signature


def verify_message(plaintext_message, message_signature, public_key, n_value):
    message_in_decmial = convert_str_to_decmial(plaintext_message)
    # decrypt the signature using public key
    operation = pow(message_signature, public_key, n_value)
    is_valid = operation == message_in_decmial
    return is_valid


# testing
# from generate_rsa import generate_rsa
# private_key, public_key, n_value = generate_rsa()

# message_signature = sign_message("hello", private_key, n_value)
# is_valid = verify_message(
#     "hello",
#     message_signature,
#     public_key,
#     n_value,
# )

# print(message_signature)
# print(is_valid)
