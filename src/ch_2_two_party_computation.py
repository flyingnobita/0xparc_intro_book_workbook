from base64 import b64decode, b64encode
from typing import Any, Dict, List, Tuple, Union

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import ElGamal

import json
import random


# Create an input array of 2-bits
input_x_array = [0, 1]
input_y_array = [0, 1]
input_array = [f"{x}{y}" for x in input_x_array for y in input_y_array]


# Given a plaintext and a password, encrypt it and return the initialization vector
# and ciphertext in bytes
def encrypt_data(
    password: bytes, plaintext: Union[str, bytes], input_as_bytes: bool = False
) -> Tuple[bytes, bytes]:
    """Encrypt data using AES in CBC mode.

    Args:
        password: The encryption key.
        plaintext: The data to encrypt, either as string or bytes.
        input_as_bytes: If True, treats plaintext as bytes, otherwise as string.

    Returns:
        Tuple containing (initialization_vector, ciphertext_bytes).
    """
    cipher = AES.new(password, AES.MODE_CBC)
    initialization_vector = cipher.iv
    if input_as_bytes:
        ciphertext_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    else:
        ciphertext_bytes = cipher.encrypt(
            pad(plaintext.encode("utf-8"), AES.block_size)
        )
    return initialization_vector, ciphertext_bytes


# Given a password, ciphertext, and initialization vector, decrypt the ciphertext
def decrypt_data(
    password: bytes,
    ciphertext_bytes: bytes,
    initialization_vector: bytes,
    input_as_bytes: bool = False,
) -> Union[str, bytes]:
    """Decrypt data using AES in CBC mode.

    Args:
        password: The decryption key.
        ciphertext_bytes: The encrypted data.
        initialization_vector: The IV used during encryption.
        input_as_bytes: If True, returns bytes, otherwise decodes to string.

    Returns:
        Decrypted data as either string or bytes.
    """
    cipher = AES.new(password, AES.MODE_CBC, initialization_vector)
    if input_as_bytes:
        plaintext = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
    else:
        plaintext = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size).decode(
            "utf-8"
        )
    return plaintext


# Using a XOR gate as an example


# Compute the output of the XOR gate
def xor_gate(x: str, y: str) -> str:
    """Compute XOR of two binary inputs.

    Args:
        x: First binary input ('0' or '1').
        y: Second binary input ('0' or '1').

    Returns:
        XOR result as '0' or '1'.
    """
    return "0" if x == y else "1"


# Store the output of the XOR gate for each input
plain_xor_gate_outputs = [xor_gate(x, y) for x in input_x_array for y in input_y_array]
plain_xor_gate_outputs


# Generate a basic garbled gate based on a plain gate output
def generate_garble_gate(
    plain_gate_outputs: List[str],
) -> Tuple[List[bytes], List[bytes], List[bytes]]:
    """Generate a garbled gate from plain gate outputs.

    Args:
        plain_gate_outputs: List of plain gate outputs ('0' or '1').

    Returns:
        Tuple containing (passwords, initialization_vectors, garbled_gate_outputs).
    """

    passwords = []
    initialization_vectors = []
    garbled_gate_outputs = []

    # Generate ciphertext for each gate output
    for message_index in range(len(plain_gate_outputs)):
        # Convert the input to bytes
        data = plain_gate_outputs[message_index]

        # Generate a random key for each input and save it to the password array
        passwords.append(get_random_bytes(16))

        # Encrypt the data using the password
        initialization_vector, ciphertext_bytes = encrypt_data(
            passwords[message_index], data
        )

        # Save the initialization vector and ciphertext to the arrays
        initialization_vectors.append(initialization_vector)
        garbled_gate_outputs.append(ciphertext_bytes)

    return passwords, initialization_vectors, garbled_gate_outputs


passwords_garbled_gate, initialization_vectors_garbled_gate, outputs_garbled_gate = (
    generate_garble_gate(plain_xor_gate_outputs)
)

## Find the output of the garbled gate from a chosen input
chosen_input = "11"

# Lookup the index for the chosen input
index_chosen_input = input_array.index(chosen_input)

# Get the password, initialization vector, and ciphertext for the chosen input
password_chosen_input = passwords_garbled_gate[index_chosen_input]
initialization_vector_chosen_input = initialization_vectors_garbled_gate[
    index_chosen_input
]
ciphertext_chosen_input = outputs_garbled_gate[index_chosen_input]

# Decrypt the ciphertext to get our gate output
gate_output = decrypt_data(
    password_chosen_input, ciphertext_chosen_input, initialization_vector_chosen_input
)

# Check that the output is correct
assert gate_output == plain_xor_gate_outputs[index_chosen_input]


### 2.1.4 Chaining garbled gates


# Hash function to combine the two inputs
def hash_function(x: bytes, y: bytes) -> bytes:
    """Combine two inputs using SHA3-256 hash.

    Args:
        x: First input bytes.
        y: Second input bytes.

    Returns:
        Combined hash digest.
    """
    hash_object = SHA3_256.new()
    # Update the hash object with the bytes of the input
    hash_object.update(x)
    hash_object.update(y)
    return hash_object.digest()


# Generate passwords for inputs x, y, z and outputs as
# bit_passwords["x_0"], bit_passwords["y_1"], etc.
bit_passwords = {
    f"{var}_{bit}": get_random_bytes(16)
    for var in ["x", "y", "z", "out"]
    for bit in ["0", "1"]
}


# Encrypt all bits with their corresponding passwords
# encrypted_bits = {
#     name: encrypt_data(password, name[-1]) for name, password in bit_passwords.items()
# }


# Construct Intermediate Garbled AND gate
def construct_intermediate_garbled_and_gate(bit_passwords: Dict[str, bytes]):
    intermediate_garbled_gate = {}
    for x_bit in [0, 1]:
        for y_bit in [0, 1]:

            # Compute hash of input passwords
            hash_key = hash_function(
                bit_passwords[f"x_{x_bit}"], bit_passwords[f"y_{y_bit}"]
            )

            # Compute AND gate output as bytes
            output_bit_password = bit_passwords[f"out_{x_bit & y_bit}"]

            # Encrypt the output with the hash key
            iv, ciphertext = encrypt_data(
                hash_key, output_bit_password, input_as_bytes=True
            )

            intermediate_garbled_gate[hash_key] = (iv, ciphertext)

    return intermediate_garbled_gate


and_garbled_gate = construct_intermediate_garbled_and_gate(bit_passwords)

### 2.1.5 How Bob uses one gate

# Using the AND gate as an example
#
#                AND
#   P_left  x ---.
#                 )--- P_output_1
#   P_right y ---'


# Lookup the garbled gate for input P_left, P_right
P_left = bit_passwords["x_0"]
P_right = bit_passwords["y_1"]

# Compute the hash of the input passwords
password_hashed_and_gate = hash_function(P_left, P_right)

# Lookup the row in the garbled gate
iv_and_gate, ciphertext_and_gate = and_garbled_gate[password_hashed_and_gate]

# Decrypt the row
P_output_1 = decrypt_data(
    password_hashed_and_gate, ciphertext_and_gate, iv_and_gate, input_as_bytes=True
)

assert P_output_1 == bit_passwords["out_0"]

#### Example: How to chain two garbled gates

# We have 2 garbled gates, and we want to chain them together

#                 AND
#    P_left  x ---.           XOR
#                  )--- P_output_1 ---.
#    P_right y ---'                    }=--- Output_plaintext
#                                     '
#    P_z -----------------------------'

# -------------------------------  XOR Gate Table -------------------------------
# hash(P_0^P_output_1, P_0^z)   | Enc_{P_0^P_output_1, P_0^z}(Output_Plaintext_0)
# hash(P_0^P_output_1, P_1^z)   | Enc_{P_0^P_output_1, P_1^z}(Output_Plaintext_1)
# hash(P_1^P_output_1, P_1^z)   | Enc_{P_1^P_output_1, P_1^z}(Output_Plaintext_1)
# hash(P_1^P_output_1, P_1^z)   | Enc_{P_1^P_output_1, P_1^z}(Output_Plaintext_0)


# Construct Final Garbled gate: XOR(x, y)
def construct_final_garbled_gate(bit_passwords: Dict[str, bytes]):
    final_garbled_gate = {}
    for out_bit in [0, 1]:
        for z_bit in [0, 1]:

            # Compute hash of input passwords
            hash_key = hash_function(
                bit_passwords[f"out_{out_bit}"], bit_passwords[f"z_{z_bit}"]
            )

            # Compute XOR gate output as bytes
            output_xor_gate_bytes = (
                "0".encode("utf-8") if out_bit == z_bit else "1".encode("utf-8")
            )

            # Encrypt the output with the hash key
            iv, ciphertext = encrypt_data(
                hash_key, output_xor_gate_bytes, input_as_bytes=True
            )

            final_garbled_gate[hash_key] = (iv, ciphertext)

    return final_garbled_gate


xor_garbled_gate = construct_final_garbled_gate(bit_passwords)

# Lookup the AND garbled gate for input P_0_left, P_1_right
P_left = bit_passwords["x_1"]
P_right = bit_passwords["y_1"]
P_z = bit_passwords["z_1"]

# Retrieve the password from the AND garbled gate
hash_password_and_gate = hash_function(P_left, P_right)
iv_and_gate, ciphertext_and_gate = and_garbled_gate[hash_password_and_gate]
password_and_gate_output_decrypted = decrypt_data(
    hash_password_and_gate, ciphertext_and_gate, iv_and_gate, input_as_bytes=True
)

# Retrieve the output of the XOR garbled gate
iv_xor_gate, ciphertext_xor_gate = xor_garbled_gate[
    hash_function(password_and_gate_output_decrypted, P_z)
]
password_chosen_input = hash_function(password_and_gate_output_decrypted, P_z)
output_xor_gate_bytes = decrypt_data(
    password_chosen_input, ciphertext_xor_gate, iv_xor_gate, input_as_bytes=True
)

assert output_xor_gate_bytes.decode("utf-8") == "0"

### 2.2 Oblivious transfer

#### 2.2.1 Commutative encryption

alice_messages = ["msg_0", "msg_1", "msg_2"]
alice_messages_encoded = [
    int.from_bytes(msg.encode("utf8"), "big") for msg in alice_messages
]

##### Step 1: Alice encrypts the messages and send it to Bob

# Alice: create a secret key which is a random integer (make it larger to handle encoded messages)
alice_secret_key = random.randint(0, 2**64)

# Alice: encrypts each message with her secret key
alice_messages_encrypted = [
    alice_secret_key ^ message for message in alice_messages_encoded
]

# Alice: sends the encrypted messages to Bob
bob_messages_encrypted = alice_messages_encrypted

##### Step 2: Bob encrypts the message with his secret key and sends it back to Alice

# Bob: wants to learn the 3rd message
message_index = 2
bob_message_to_decrypt = bob_messages_encrypted[message_index]

# Bob: creates a secret key which is a random integer
bob_secret_key = random.randint(0, 2**64)

# Bob: encrypts the message with his secret key
bob_message_to_decrypt_reencrypted = bob_message_to_decrypt ^ bob_secret_key

# Bob: sends the encrypted message to Alice
alice_message_to_decrypt = bob_message_to_decrypt_reencrypted

##### Step 3: Alice decrypts the message from Bob and sends it back to Bob

# Alice: decrypts the message with her key
alice_message_decrypted = alice_message_to_decrypt ^ alice_secret_key

# Alice: send message back to Bob
bob_message_to_decrypt = alice_message_decrypted

##### Step 4: Bob decrypts the message from Alice

# Bob: decrypts the message with his key
bob_message_decrypted = bob_message_to_decrypt ^ bob_secret_key

# Convert the message from integer back to a string
bob_message_final = bob_message_decrypted.to_bytes(
    (bob_message_decrypted.bit_length() + 7) // 8, "big"
).decode("utf8")

# Assert that the message is correct
assert bob_message_final == alice_messages[message_index]

### 2.2.3 OT in one step

# Public: r is a verifiably random number in integer
# As example, we use r = sha(1)
r = int.from_bytes(SHA3_256.new(b"1").digest(), "big")


# TODO Modify the function such that Alice can verify that the keys have a difference of r
# Generate a set of RSA keys in arithmetic progression
def generate_ap_rsa_keys(
    index_genuine_key: int,
    number_of_keys: int,
    progression_step: int,
    key_size: int = 3072,
) -> List[RSA.RsaKey]:
    """Generate RSA keys in arithmetic progression.

    Args:
        index_genuine_key: Index of the genuine key in the sequence.
        number_of_keys: Total number of keys to generate.
        progression_step: Step size between consecutive keys.
        key_size: Size of RSA key in bits.

    Returns:
        List of RSA private keys.
    """
    # Generate the first key
    key_i = RSA.generate(key_size)

    # Create the set of RSA modulus n in arithmetic progression
    n_set = [
        key_i.n + (j - index_genuine_key) * progression_step
        for j in range(number_of_keys)
    ]

    # Construct all the keys
    e = 65537
    private_key_set = [RSA.construct((n_set[j], e)) for j in range(number_of_keys)]
    # Replace the ith key with key_i
    private_key_set[index_genuine_key] = key_i

    return private_key_set


def generate_ot_keys(
    index_genuine_key: int, number_of_keys_to_generate: int, r: int
) -> Tuple[List[RSA.RsaKey], List[RSA.RsaKey]]:
    """Generate key pairs for oblivious transfer.

    Args:
        index_genuine_key: Index of the genuine key.
        number_of_keys_to_generate: Number of key pairs to generate.
        r: Random number for arithmetic progression.

    Returns:
        Tuple containing (private_key_set, public_key_set).
    """
    private_key_set = generate_ap_rsa_keys(
        index_genuine_key,
        number_of_keys_to_generate,
        progression_step=r,
    )

    public_key_set = [key.public_key() for key in private_key_set]

    return private_key_set, public_key_set


# Bob: assume Bob wants to learn the 2nd message
message_index = 1

# Bob: create a set of keys based on r to which Alice can verify they
# all have a difference of r, thus proving that Bob only knows the secret key
# to one of the public keys
bob_private_key_set, bob_public_key_set = generate_ot_keys(
    message_index,
    len(alice_messages),
    r,
)


# Alice: use the public keys from Bob to encrypt her messages
def ot_encrypt_messages(
    messages: List[Union[str, bytes]],
    public_key_set: List[RSA.RsaKey],
) -> List[bytes]:
    """Encrypt messages using oblivious transfer public keys.

    Args:
        messages: List of messages to encrypt.
        public_key_set: List of RSA public keys.

    Returns:
        List of encrypted messages.
    """
    encrypted_messages = []
    for j in range(len(messages)):
        cipher = PKCS1_OAEP.new(public_key_set[j])

        # Check if message is already in bytes format
        if isinstance(messages[j], bytes):
            encrypted_messages.append(cipher.encrypt(messages[j]))
        else:
            encrypted_messages.append(cipher.encrypt(messages[j].encode("utf8")))
    return encrypted_messages


alice_messages_encrypted = ot_encrypt_messages(alice_messages, bob_public_key_set)

# Alice: send the encrypted messages to Bob
bob_messages_encrypted = alice_messages_encrypted


# Bob: decrypt the messages that Alice sent
def ot_decrypt_messages(
    messages: List[bytes],
    private_key_set: List[RSA.RsaKey],
    index_genuine_key: int,
    output_as_str: bool = True,
) -> Union[str, bytes]:
    """Decrypt message using oblivious transfer private key.

    Args:
        messages: List of encrypted messages.
        private_key_set: List of RSA private keys.
        index_genuine_key: Index of the genuine key to use.
        output_as_str: If True, returns string, else bytes.

    Returns:
        Decrypted message as either string or bytes.
    """
    cipher = PKCS1_OAEP.new(private_key_set[index_genuine_key])
    if output_as_str:
        return cipher.decrypt(messages[index_genuine_key]).decode("utf8")
    else:
        return cipher.decrypt(messages[index_genuine_key])


bob_messages_decrypted = ot_decrypt_messages(
    bob_messages_encrypted, bob_private_key_set, message_index
)

assert bob_messages_decrypted == alice_messages[message_index]

#### Example: How To Combine Garbled Circuits and OT

# Convert bit_passwords to a list
bit_passwords_key_list = list(bit_passwords.keys())
bit_password_value_list = list(bit_passwords.values())
# ['x_0', 'x_1', 'y_0', 'y_1', 'z_0', 'z_1', 'out_0', 'out_1']

# Define the password that Bob wants to learn
bob_password_to_learn = "x_1"

# Bob: Find the index of password in question on the list
bob_password_index = bit_passwords_key_list.index(bob_password_to_learn)

# Bob: generate the keys for the OT
bob_private_key_set, bob_public_key_set = generate_ot_keys(
    bob_password_index,
    len(bit_password_value_list),
    r,
)

# Alice: use Bob's public keys to encrypt all the bit_passwords
alice_bit_passwords_encrypted = ot_encrypt_messages(
    bit_password_value_list, bob_public_key_set
)

# Alice: send the encrypted bit_passwords to Bob
bob_bit_passwords_encrypted = alice_bit_passwords_encrypted

# Bob: decrypt the encrypted bit_passwords
bob_bit_passwords_decrypted = ot_decrypt_messages(
    bob_bit_passwords_encrypted,
    bob_private_key_set,
    bob_password_index,
    output_as_str=False,
)

# Assert that the decrypted bit_passwords are correct
assert bob_bit_passwords_decrypted == bit_passwords["x_1"]

# Bob can now use the password for P_left in the garbled circuit
