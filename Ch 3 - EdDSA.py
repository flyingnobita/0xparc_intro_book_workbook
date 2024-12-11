# 3 SNARKs Prelude: Elliptic Curves and Polynomial Commitments

## 3.2.2 EdDSA Signature Scheme

import random
import hashlib


### Setup edwards25519 curve
# The curve parameters for edwards25519, Twisted Edwards curve
# p: The prime field characteristic (2^255 - 19)
# q: The prime order of the base point (number of points in the subgroup)
p = 2**255 - 19
q = 2**252 + 277423177773723535340499608640600641176714606484999
# a, d: Curve coefficients for the equation: ax^2 + y^2 = 1 + dx^2y^2
a = -1
d = -(121665 * pow(121666, -1, p))

# Define the base point Q

# The standard base point Q(x, y) for Ed25519 is based on the standard base point
# P for the X25519 Diffie-Hellman function.
# P(u, v) = (9, v) where we only care about the x-coordinate, u.
# Q(x, y) where y(Q) = (u(P) - 1) / (u(P) + 1)
u_P = 9
y_Q = (u_P - 1) * pow(u_P + 1, -1, p)

# x(Q) is calculated from y(Q) using the curve equation
x_Q = 15112221349535400772501151409588531511454012693041857206046113283949847762202

# Verify base point Q with the curve equation
assert (-(x_Q**2) + (y_Q**2)) % p == (1 + d * (x_Q**2) * (y_Q**2)) % p

# Base point Q
Q = (x_Q, y_Q)


# Addition of two points on the curve
# Reference: https://en.wikipedia.org/wiki/Twisted_Edwards_curve
def points_addition(P1, P2):
    """Add two points on the edwards25519 curve using the twisted Edwards addition formula:
    x3 = (x1y2 + y1x2) / (1 + dx1x2y1y2)
    y3 = (y1y2 - ax1x2) / (1 - dx1x2y1y2)
    """
    x_P1, y_P1 = P1
    x_P2, y_P2 = P2

    x_result = (
        ((x_P1 * y_P2 + y_P1 * x_P2) % p)
        * pow(1 + d * x_P1 * x_P2 * y_P1 * y_P2, -1, p)
    ) % p
    y_result = (
        ((y_P1 * y_P2 - a * x_P1 * x_P2) % p)
        * pow(1 - d * x_P1 * x_P2 * y_P1 * y_P2, -1, p)
    ) % p

    # ensure the new point is fits the curve equation:
    # (a * x^2 + y^2) mod p = (1 + d * x^2 * y^2) mod p
    assert (a * x_result * x_result + y_result * y_result) % p == (
        1 + d * x_result * x_result * y_result * y_result
    ) % p

    return (x_result, y_result)


# Multiplication of a point on the curve with a scalar using the double-and-add algorithm
# Reference: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
def points_multiplication(point, scalar):
    """Multiply a point by a scalar using the double-and-add algorithm:
    1. Convert scalar to binary
    2. For each bit:
       - Double the accumulated point
       - If bit is 1, add the base point
    3. Return the final accumulated point
    """
    if scalar == 0:
        return (0, 1)  # Return point at infinity (neutral element)

    result = None
    scalar_in_binary = bin(scalar)[2:]  # convert scalar to binary, removing '0b' prefix

    for bit in scalar_in_binary:
        # double
        if result is not None:
            result = points_addition(result, result)
        else:
            result = point

        # add if the current bit is 1
        if bit == "1" and result != point:
            result = points_addition(result, point)

    # ensure the new point is fits the curve equation:
    # (a * x^2 + y^2) mod p = (1 + d * x^2 * y^2) mod p
    assert (a * result[0] * result[0] + result[1] * result[1]) % p == (
        1 + d * result[0] * result[0] * result[1] * result[1]
    ) % p

    return result


### Algorithm 3.9: Public and Secret Keys
# Generate a random private key (scalar) and compute the corresponding public key
# public_key = [private_key]Q where Q is the base point
randomness_bit_size = 252
private_key = random.getrandbits(randomness_bit_size)
public_key = points_multiplication(Q, private_key)


### Algorithm 3.10: EdDSA Signature Generation
# The signature consists of two parts:
# 1. r_public: A point [r]Q where r is a random scalar
# 2. s: A scalar computed as r + (private_key * hash(r_public || message || public_key))
message = "Hello world"

#### Step 1: Generate random scalar r ∈ 𝔽𝑞 and publishes [r] ∈ 𝔽𝑞
r_secret = random.getrandbits(randomness_bit_size)
r_public = points_multiplication(Q, r_secret)

#### Step 2: Generate a number n ∈ 𝔽𝑞 by hashing the message with all public information
n = (
    int(
        hashlib.sha256(
            (str(r_public) + str(message) + str(public_key)).encode("utf-8")
        ).hexdigest(),
        16,
    )
    % q
)

#### Step 3: Compute integer s := (r + d * n) mod q
s = r_secret + private_key * n

#### Signature is ready
signature = (r_public, s)

### Algorithm 3.11: EdDSA Signature Verification
# Verify the signature by checking:
# [s]Q = [r]Q + [hash(r_public || message || public_key)]public_key
# This proves the signer knows the private key without revealing it

#### Step 1: Compute n = hash(r_public, message, public_key)
n_verification = (
    int(
        hashlib.sha256(
            (str(r_public) + str(message) + str(public_key)).encode("utf-8")
        ).hexdigest(),
        16,
    )
    % q
)

# Compute [s] ∈ 𝐸
s_armored = points_multiplication(Q, s)

#### Step 2: Verify [r] + n * public_key == [s]
n_mul_public_key = points_multiplication(public_key, n_verification)
lhs = points_addition(r_public, n_mul_public_key)
rhs = s_armored
assert lhs[0] == rhs[0]
assert lhs[1] == rhs[1]
