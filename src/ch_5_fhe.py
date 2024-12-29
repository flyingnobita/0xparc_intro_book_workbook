# 5. FHE

## 5.3.2 Public Key Cryptography from LWE - Encryption Example

import random

public_key = [
    [[1, 0, 1, 7], 2],
    [[5, 8, 4, 10], 2],
    [[7, 7, 8, 5], 3],
    [[5, 1, 10, 6], 10],
    [[8, 0, 2, 4], 9],
    [[9, 3, 0, 6], 9],
    [[0, 6, 1, 6], 9],
    [[0, 4, 9, 7], 5],
    [[10, 7, 4, 10], 10],
    [[5, 5, 10, 6], 9],
    [[10, 7, 3, 1], 9],
    [[0, 2, 5, 5], 6],
    [[9, 10, 2, 1], 3],
    [[3, 7, 2, 1], 6],
    [[2, 3, 4, 5], 3],
    [[2, 1, 6, 9], 3],
]

# randomly choose 4 rows from the public key
number_of_rows_to_choose = 4
public_key_chosen = random.sample(public_key, number_of_rows_to_choose)
print(f"public_key_chosen: {public_key_chosen}")

# set the modulus q
q = 11

# message m is randomly either 0 or 5
m = random.choice([0, 5])


def encrypt(public_key_chosen, q, m):
    # Calculate x: For every row of the public key, sum each element of the first item
    # modulo q. e.g. 1 + 5 + 7 + 5 = 18 % 11 = 7
    x = []
    for element in range(len(public_key_chosen[0][0])):
        running_sum = 0
        for row in public_key_chosen:
            running_sum += row[0][element]
        x.append(running_sum % q)

    # Calculate y_0: Sum the second item of every row modulo q
    y_0 = sum([pair[1] for pair in public_key_chosen]) % q

    # Calculate the ciphertext
    y = y_0 - m
    ciphertext = [x, y]

    return ciphertext


ciphertext = encrypt(public_key_chosen, q, m)

## 5.3.3 Decrypt the ciphertext

# private key a
a = [10, 8, 10, 10]


def decrypt(ciphertext, private_key, modulus):

    # x ⋅ a + 𝜖 = y + m where 0 ≤ 𝜖 ≤ 4

    # calculate x ⋅ a
    x_dot_a = (
        sum([ciphertext[0][i] * private_key[i] for i in range(len(ciphertext[0]))])
        % modulus
    )

    # let m' be our decoded message (whereas m is our original message)
    # x ⋅ a + 𝜖 = y + m'
    # we know m' is either 0 or 5, and 0 ≤ 𝜖 ≤ 4
    for e in range(5):
        m_prime = (x_dot_a - ciphertext[1] + e) % modulus
        if m_prime in {0, 5}:
            break

    return m_prime


decoded_message = decrypt(ciphertext, a, q)

assert decoded_message == m

## 5.4.1

# secret key 𝐯 is a vector of length n
# 𝐯 = (𝑣_1, …, 𝑣_𝑛) ∈ (ℤ/𝑞ℤ)^𝑛
v = [1, 2, 10, 1]


# message 𝜇
# 𝜇 ∈ {0, 1}
mu = 1


# Ciphertext 𝐶 is a square n-by-n matrix

# 𝐶𝐯 ≈ 𝜇𝐯
# i.e. Ciphertext * secret key ≈ message * secret key


## 5.4.3 The "Flatten" Operation

# let r = 1, 𝐯 = (𝑎_1, 2𝑎_1, 4𝑎_1, 8𝑎_1)
v = [1, 2, 4, 8]

# set the modulus q
q = 11

x_1 = [9, 0, 0, 0]

### Problem 5.4: How to flatten 𝐱 = (9, 3, 1, 4)?
x_2 = [9, 3, 1, 4]


def flatten(x, v, modulus):

    # calculate x_dot_v
    x_dot_v = sum([x[i] * v[i] for i in range(len(x))]) % modulus

    # convert x_dot_v to binary representation with leading 0s
    return bin(x_dot_v)[2:].zfill(len(v))


print("x_prime_1:", flatten(x_1, v, q))
print("x_prime_2:", flatten(x_2, v, q))
