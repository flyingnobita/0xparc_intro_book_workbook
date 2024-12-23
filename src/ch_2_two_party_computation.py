import json
import random
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

### 2.1.3 Garbled gates

# Create an input array of 2-bits
input_x_array = [0, 1]
input_y_array = [0, 1]
input_array = [f"{x}{y}" for x in input_x_array for y in input_y_array]


# Compute the output of the XOR gate
def xor_gate(x, y):
    return "0" if x == y else "1"


# Given a plaintext and a password, encrypt it and return the initialization vector
# and ciphertext in bytes
def encrypt_data(password, plaintext, input_as_bytes=False):
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
    password, ciphertext_bytes, initialization_vector, input_as_bytes=False
):
    cipher = AES.new(password, AES.MODE_CBC, initialization_vector)
    if input_as_bytes:
        plaintext = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
    else:
        plaintext = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size).decode(
            "utf-8"
        )
    return plaintext


# Store the output of the XOR gate for each input
plain_gate_outputs = [xor_gate(x, y) for x in input_x_array for y in input_y_array]


# Create arrays to save the password, initialization vector, and ciphertext
passwords = []
initialization_vectors = []
garbled_gate_outputs = []


# Generate ciphertext for each gate output
for index_bob_message in range(len(plain_gate_outputs)):
    # Convert the input to bytes
    data = plain_gate_outputs[index_bob_message]

    # Generate a random key for each input and save it to the password array
    passwords.append(get_random_bytes(16))

    # Encrypt the data using the password
    initialization_vector, ciphertext_bytes = encrypt_data(
        passwords[index_bob_message], data
    )

    # Save the initialization vector and ciphertext to the arrays
    initialization_vectors.append(initialization_vector)
    garbled_gate_outputs.append(ciphertext_bytes)


## Bob: Decrypt the ciphertext for x = 0, y = 1

# Lookup the index for input x = 0, y = 1
index = input_array.index("01")

# Get the password, initialization vector, and ciphertext for the 4th row
password = passwords[index]
initialization_vector = initialization_vectors[index]
ciphertext_bytes = garbled_gate_outputs[index]

# Decrypt the ciphertext
plaintext = decrypt_data(password, ciphertext_bytes, initialization_vector)

# Check that the output is 1 since XOR(0, 1) = 1
assert plaintext == "1"


### 2.1.4 Chaining garbled gates


# Hash function to combine the two inputs
def hash_function(x, y):
    hash_object = SHA3_256.new()
    # Update the hash object with the bytes of the input
    hash_object.update(x)
    hash_object.update(y)
    return hash_object.digest()


# Define the inputs bits and output bits
input_bit_x_0 = "0"
input_bit_x_1 = "1"
input_bit_y_0 = "0"
input_bit_y_1 = "1"
input_bit_z_0 = "0"
input_bit_z_1 = "1"
output_bit_0 = "0"
output_bit_1 = "1"

# Generate passwords and create arrays to save the passwords for each gate
input_bit_x_0_password = get_random_bytes(16)
input_bit_x_1_password = get_random_bytes(16)
input_bit_y_0_password = get_random_bytes(16)
input_bit_y_1_password = get_random_bytes(16)
input_bit_z_0_password = get_random_bytes(16)
input_bit_z_1_password = get_random_bytes(16)
output_bit_0_password = get_random_bytes(16)
output_bit_1_password = get_random_bytes(16)

input_bit_x_0_iv, input_bit_x_0_encrypted = encrypt_data(
    input_bit_x_0_password, input_bit_x_0
)
input_bit_x_1_iv, input_bit_x_1_encrypted = encrypt_data(
    input_bit_x_1_password, input_bit_x_1
)
input_bit_y_0_iv, input_bit_y_0_encrypted = encrypt_data(
    input_bit_y_0_password, input_bit_y_0
)
input_bit_y_1_iv, input_bit_y_1_encrypted = encrypt_data(
    input_bit_y_1_password, input_bit_y_1
)
input_bit_z_0_iv, input_bit_z_0_encrypted = encrypt_data(
    input_bit_z_0_password, input_bit_z_0
)
input_bit_z_1_iv, input_bit_z_1_encrypted = encrypt_data(
    input_bit_z_1_password, input_bit_z_1
)
output_bit_0_iv, output_bit_0_encrypted = encrypt_data(
    output_bit_0_password, output_bit_0
)
output_bit_1_iv, output_bit_1_encrypted = encrypt_data(
    output_bit_1_password, output_bit_1
)


# Construct Garbled gate: AND(x, y)
and_garbled_gate = {}
for x_bit, x_password in [(0, input_bit_x_0_password), (1, input_bit_x_1_password)]:
    for y_bit, y_password in [(0, input_bit_y_0_password), (1, input_bit_y_1_password)]:
        # Compute hash of input passwords
        hash_key = hash_function(x_password, y_password)
        # Compute AND gate output
        output = "0" if x_bit & y_bit == 0 else "1"
        # Encrypt the output
        if output == "0":
            iv, ciphertext = encrypt_data(
                hash_key, output_bit_0_password, input_as_bytes=True
            )
        else:
            iv, ciphertext = encrypt_data(
                hash_key, output_bit_1_password, input_as_bytes=True
            )
        # Store in garbled gate
        and_garbled_gate[hash_key] = (iv, ciphertext)

### 2.1.5 How Bob uses one gate

# Bob: Lookup the garbled gate for input P_0_left, P_1_right
P_0_left = input_bit_x_0_password
P_1_right = input_bit_y_1_password

hash_passwords = hash_function(P_0_left, P_1_right)

# Bob: Lookup the row in the garbled gate
iv, ciphertext = and_garbled_gate[hash_passwords]

# Bob: Decrypt the row
P_0_output = decrypt_data(hash_passwords, ciphertext, iv, input_as_bytes=True)
assert P_0_output == output_bit_0_password

### TODO: Example of how to chain garbled gates

# We have 2 garbled gates, and we want to chain them together
# 1st gate: AND(x, y)
# 2nd gate: XOR(AND(x, y), z)

# Alice: Send the encrypted outputs to Bob

# Bob: Decrypt the output of the second gate


### 2.2 Oblivious transfer

#### 2.2.1 Commutative encryption

alice_messages = ["msg_1", "msg_2", "msg_3"]
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
bob_message_to_decrypt = bob_messages_encrypted[2]

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
assert bob_message_final == alice_messages[2]

### 2.2.3 OT in one step

# Public: r is a verifiably random number in integer
r = int.from_bytes(SHA3_256.new(b"1").digest(), "big")


# Generate a set of RSA keys in arithmetic progression
def generate_ap_rsa_keys(
    index_genuine_key, number_of_keys=3, progression_step=1000, key_size=3072
):
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


# Bob: assume Bob wants to learn the 2nd message
index_bob_message = 0

# For each message, a unique key is generated
number_of_keys_to_generate = len(alice_messages)

# Bob: create a set of keys based on r to which Alice can verify they
# all have a difference of r, thus proving that Bob only knows the secret key
# to one of the public keys
bob_private_key_set = generate_ap_rsa_keys(
    index_genuine_key=index_bob_message,
    number_of_keys=number_of_keys_to_generate,
    progression_step=r,
)

# Bob: create the set of public keys from the private keys
bob_public_key_set = [key.public_key() for key in bob_private_key_set]

# Alice: use the public keys from Bob to encrypt her messages
for j in range(number_of_keys_to_generate):
    cipher = PKCS1_OAEP.new(bob_public_key_set[j])
    alice_messages_encrypted[j] = cipher.encrypt(alice_messages[j].encode("utf8"))


# Alice: send the encrypted messages to Bob
bob_messages_encrypted = alice_messages_encrypted

# Bob: decrypt the message that Alice sent
cipher = PKCS1_OAEP.new(bob_private_key_set[index_bob_message])
bob_messages_decrypted = cipher.decrypt(
    bob_messages_encrypted[index_bob_message]
).decode("utf8")

# Assert that the messages are correct
assert bob_messages_decrypted == alice_messages[index_bob_message]

# TODO Combine Garbled Circuits and OT
