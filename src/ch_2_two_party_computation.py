import random
from typing import Dict, List, Tuple, Union

from Crypto.Hash import SHA3_256

from ch_2_elgamal import ElGamal
from utils import extend_byte_with_leading_zeros


## Setup ElGamal, our encryption scheme used for this chapter

# Create a new ElGamal encryption object and generate keys
elgamal = ElGamal()
elgamal.generate_keys()

# Using a XOR gate as an example

# Create an input array of 2-bits
input_x_array = [0, 1]
input_y_array = [0, 1]
input_array = [f"{x}{y}" for x in input_x_array for y in input_y_array]


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


# Construct a basic garbled gate based on a plain gate output
def construct_garble_gate(
    plain_gate_outputs: List[str],
    elgamal: ElGamal,
) -> Tuple[List[Tuple[int, int, int]], List[int], List[Tuple[int, int]]]:
    """Construct a garbled gate from plain gate outputs.

    Args:
        plain_gate_outputs: List of plain gate outputs ('0' or '1').
        elgamal: ElGamal object.

    Returns:
        Tuple containing (passwords, initialization_vectors, garbled_gate_outputs).
    """

    passwords = []
    initialization_vectors = []
    garbled_gate_outputs = []

    public_keys = []
    private_keys = []

    # Generate ciphertext for each gate output
    for message_index in range(len(plain_gate_outputs)):
        # Convert the input to bytes
        data = plain_gate_outputs[message_index]

        # Generate a random key for each input and save it to the password array
        public_key, private_key = elgamal.generate_keys_from_prime(elgamal.p, elgamal.g)
        public_keys.append(public_key)
        private_keys.append(private_key)

        # Encrypt the data using the public key
        ciphertext = elgamal.encrypt(data, public_key)

        # Save the initialization vector and ciphertext to the arrays
        garbled_gate_outputs.append(ciphertext)

    return public_keys, private_keys, garbled_gate_outputs


public_keys_garbled_gate, private_keys_garbled_gate, outputs_garbled_gate = (
    construct_garble_gate(plain_xor_gate_outputs, elgamal)
)

## Find the output of the garbled gate from a chosen input
chosen_input = "11"

# Lookup the index for the chosen input
index_chosen_input = input_array.index(chosen_input)

# Get the public key, private key, and ciphertext for the chosen input
public_key_chosen_input = public_keys_garbled_gate[index_chosen_input]
private_key_chosen_input = private_keys_garbled_gate[index_chosen_input]
ciphertext_chosen_input = outputs_garbled_gate[index_chosen_input]

gate_output = elgamal.decrypt(
    ciphertext=ciphertext_chosen_input,
    private_key=private_key_chosen_input,
    output_bytes=False,
)

# Check that the output is correct
print(f"gate_output: {gate_output}")
print(
    f"plain_xor_gate_outputs[index_chosen_input]: {plain_xor_gate_outputs[index_chosen_input]}"
)
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


password_bit_length = 128

bit_passwords = {
    f"{var}_{bit}": random.randrange(2, ((1 << password_bit_length) - 1)).to_bytes(
        password_bit_length, "big"
    )
    for var in ["x", "y", "z", "out"]
    for bit in ["0", "1"]
}


# Construct Intermediate Garbled AND gate
def construct_intermediate_garbled_and_gate(
    bit_passwords: Dict[str, bytes], elgamal: ElGamal
) -> Dict[bytes, Tuple[int, int]]:
    """Construct an intermediate garbled AND gate using ElGamal encryption.

    This function creates a garbled AND gate by encrypting output bit passwords
    For each possible input combination of (x_bit, y_bit), it:
    1. Computes a hash of the input passwords as a lookup key
    2. Computes the AND of the input bits
    3. Combines passwords and generates a public key from it
    4. Encrypts the output using ElGamal


    Args:
        bit_passwords: Dictionary mapping bit labels (e.g. "x_0", "y_1") to their password bytes
        elgamal: ElGamal encryption instance to use for encryption

    Returns:
        Dictionary mapping hash keys to encrypted output passwords (ElGamal ciphertexts)
    """
    intermediate_garbled_gate = {}
    for x_bit in [0, 1]:
        for y_bit in [0, 1]:
            # Compute hash of input passwords
            hash_key = hash_function(
                bit_passwords[f"x_{x_bit}"], bit_passwords[f"y_{y_bit}"]
            )

            # Compute AND gate output as bytes
            output_bit_password = bit_passwords[f"out_{x_bit & y_bit}"]

            # Combine the 2 passwords as the new password and generate the public key
            password = (
                int.from_bytes(bit_passwords[f"x_{x_bit}"], "big")
                + int.from_bytes(bit_passwords[f"y_{y_bit}"], "big")
            ) % elgamal.p
            public_key = elgamal.generate_public_key(password)

            # Encrypt the output
            ciphertext = elgamal.encrypt(
                message=output_bit_password, public_key=public_key
            )

            intermediate_garbled_gate[hash_key] = ciphertext

    return intermediate_garbled_gate


and_garbled_gate = construct_intermediate_garbled_and_gate(bit_passwords, elgamal)

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
ciphertext_and_gate = and_garbled_gate[password_hashed_and_gate]

# Combine the 2 passwords as the new password
password = (int.from_bytes(P_left, "big") + int.from_bytes(P_right, "big")) % elgamal.p

P_output_1 = elgamal.decrypt(
    ciphertext=ciphertext_and_gate,
    private_key=password,
    output_bytes=True,
)

P_output_1_int = int.from_bytes(P_output_1, "big")

# Check that the output is correct
print(f"P_output_1_int: {P_output_1_int}")
print(f"bit_passwords['out_0'] in int: {int.from_bytes(bit_passwords['out_0'], 'big')}")
assert P_output_1_int == int.from_bytes(bit_passwords["out_0"], "big")

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


# Construct Final Garbled XOR gate
def construct_final_garbled_xor_gate(
    bit_passwords: Dict[str, bytes], elgamal: ElGamal
) -> Dict[bytes, Tuple[int, int]]:
    """Construct a final garbled XOR gate using ElGamal encryption.

    This function creates a final garbled XOR gate by encrypting output bit passwords
    For each combination of input bits (out_bit and z_bit), it:
    1. Computes a hash of the input passwords as a lookup key
    2. Computes the XOR of the input bits
    3. Combines passwords and generates a public key from it
    4. Encrypts the output using ElGamal

    Args:
        bit_passwords: Dictionary mapping bit labels (e.g. "x_0", "y_1") to their password bytes
        elgamal: ElGamal encryption object used for encryption operations

    Returns:
        Dictionary mapping hash keys to encrypted gate outputs (ciphertexts)
        where each ciphertext is a tuple of (c1, c2) ElGamal components
    """
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

            # Combine the 2 passwords as the new password and generate the public key
            password = (
                int.from_bytes(bit_passwords[f"out_{out_bit}"], "big")
                + int.from_bytes(bit_passwords[f"z_{z_bit}"], "big")
            ) % elgamal.p
            public_key = elgamal.generate_public_key(password)

            # Encrypt the output
            ciphertext = elgamal.encrypt(
                message=output_xor_gate_bytes, public_key=public_key
            )

            final_garbled_gate[hash_key] = ciphertext

    return final_garbled_gate


xor_garbled_gate = construct_final_garbled_xor_gate(bit_passwords, elgamal)

# Lookup the AND garbled gate for input P_0_left, P_1_right
P_left = bit_passwords["x_1"]
P_right = bit_passwords["y_1"]
P_z = bit_passwords["z_1"]

# Retrieve the password from the AND garbled gate

# Compute the hash of the input passwords
hash_password_and_gate = hash_function(P_left, P_right)

# Lookup the row in the AND garbled gate
ciphertext_and_gate = and_garbled_gate[hash_password_and_gate]

# Combine the 2 passwords as the new password
combined_password_and_gate = (
    int.from_bytes(P_left, "big") + int.from_bytes(P_right, "big")
) % elgamal.p

# Decrypt the output of the AND garbled gate
password_and_gate_output_decrypted = elgamal.decrypt(
    ciphertext=ciphertext_and_gate,
    private_key=combined_password_and_gate,
    output_bytes=True,
)


# Retrieve and decrypt the output of the XOR garbled gate

# Process the output so it can be used as a password
password_and_gate_output_decrypted_int_bytes = extend_byte_with_leading_zeros(
    password_and_gate_output_decrypted, password_bit_length
)

# Lookup the row in the XOR garbled gate
ciphertext_xor_gate = xor_garbled_gate[
    hash_function(password_and_gate_output_decrypted_int_bytes, P_z)
]

# Combine the 2 passwords as the new password
password_chosen_input = (
    int.from_bytes(password_and_gate_output_decrypted, "big")
    + int.from_bytes(P_z, "big")
) % elgamal.p

# Decrypt the output of the XOR garbled gate
output_xor_gate_bytes = elgamal.decrypt(
    ciphertext=ciphertext_xor_gate, private_key=password_chosen_input, output_bytes=True
)

# Check that the output is correct
print(f"output_xor_gate_bytes in string: {output_xor_gate_bytes.decode('utf-8') }")
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

print("bob_message_final: ", bob_message_final)
print("alice_messages[message_index]: ", alice_messages[message_index])

# Assert that the message is correct
assert bob_message_final == alice_messages[message_index]

### 2.2.3 OT in one step

# Public: r is a verifiably random number in integer
# As example, we use r = sha(1)
r = int.from_bytes(SHA3_256.new(b"1").digest(), "big")


# Generate a set of ElGamal keys in arithmetic progression
def generate_ap_keys(
    index_genuine_key: int,
    number_of_keys: int,
    progression_step: int,
    elgamal: ElGamal = None,
) -> Tuple[List[Tuple[int, int, int]], int]:
    """Generate ElGamal keys in arithmetic progression.

    Args:
        index_genuine_key: Index of the genuine key in the sequence.
        number_of_keys: Total number of keys to generate.
        progression_step: Step size between consecutive keys.
        elgamal: ElGamal object.

    Returns:
        Tuple containing (public_keys, private_key).
    """

    # Generate the first key
    if elgamal is None:
        elgamal = ElGamal()
    (public_key, private_key) = elgamal.generate_keys()

    # Generate the keys in arithmetic progression
    public_keys_y = [
        public_key[2] + (j - index_genuine_key) * progression_step
        for j in range(number_of_keys)
    ]

    public_keys = [
        (elgamal.p, elgamal.g, public_keys_y[j]) for j in range(number_of_keys)
    ]

    return (public_keys, private_key)


# Bob: assume Bob wants to learn the 2nd message
message_index = 1

# Bob: create a set of keys based on r to which Alice can verify they
bob_public_key_set, bob_private_key = generate_ap_keys(
    message_index,
    len(alice_messages),
    r,
    elgamal,
)

# Alice: check Bob's public keys are in arithmetic progression
for j in range(len(bob_public_key_set)):
    assert bob_public_key_set[j][2] == bob_public_key_set[0][2] + j * r


# Alice: use the public keys from Bob to encrypt her messages
def ot_encrypt_messages(
    messages: List[Union[str, bytes]],
    public_key_set: List[Tuple[int, int, int]],
    elgamal: ElGamal,
) -> List[Tuple[int, int]]:
    encrypted_messages = []
    for j in range(len(messages)):
        encrypted_messages.append(elgamal.encrypt(messages[j], public_key_set[j]))
    return encrypted_messages

alice_messages_encrypted = ot_encrypt_messages(
    alice_messages, bob_public_key_set, elgamal
)


# Alice: send the encrypted messages to Bob
bob_messages_encrypted = alice_messages_encrypted


# Bob: decrypt the messages that Alice sent
bob_messages_decrypted = elgamal.decrypt(
    ciphertext=bob_messages_encrypted[message_index],
    private_key=bob_private_key,
    output_bytes=False,
)

# Check that the output is correct
print(f"bob_messages_decrypted: {bob_messages_decrypted}")
print(f"alice_messages[message_index]: {alice_messages[message_index]}")
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
bob_public_key_set, bob_private_key = generate_ap_keys(
    bob_password_index,
    len(bit_password_value_list),
    r,
    elgamal,
)


# Alice: use Bob's public keys to encrypt all the bit_passwords
alice_bit_passwords_encrypted = ot_encrypt_messages(
    bit_password_value_list, bob_public_key_set, elgamal
)

# Alice: send the encrypted bit_passwords to Bob
bob_bit_passwords_encrypted = alice_bit_passwords_encrypted

bob_bit_passwords_decrypted = elgamal.decrypt(
    ciphertext=bob_bit_passwords_encrypted[bob_password_index],
    private_key=bob_private_key,
    output_bytes=True,
)

# Check that the output is correct
print(
    f"bob_bit_passwords_decrypted in int: {int.from_bytes(bob_bit_passwords_decrypted, 'big')}"
)
print(f"bit_passwords['x_1'] in int: {int.from_bytes(bit_passwords['x_1'], 'big')}")
assert int.from_bytes(bob_bit_passwords_decrypted, "big") == int.from_bytes(
    bit_passwords["x_1"], "big"
)

# Bob can now use the password for P_left in the garbled circuit
