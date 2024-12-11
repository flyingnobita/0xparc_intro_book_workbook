# 3 SNARKs Prelude: Elliptic Curves and Polynomial Commitments

## 3.2.3 Pedersen Commitments

# This module implements Pedersen Commitments on the BN128 elliptic curve
# Pedersen Commitments allow committing to a message while hiding its contents
# (hiding property) and preventing changes to the committed message (binding property)

import random
from py_ecc.bn128 import is_on_curve, G1, multiply, add, field_modulus

### Setup the curve
# field_modulus is the order of the finite field
# b is the curve parameter in y^2 = x^3 + b
b = 3

# n is the number of elements in the message vector
n = 10


def generate_points(generator, n):
    """
    Generate n random points on the curve using the generator point
    Args:
        generator: Base point (typically G1)
        n: Number of points to generate
    Returns:
        List of n random points on the curve
    """
    points = []
    for _ in range(n):
        # Multiply generator by random scalar to get a new point
        point = multiply(generator, random.randint(1, field_modulus))
        points.append(point)
        assert is_on_curve(point, b), "Point not on curve"
    return points


def setup(n):
    """
    Initialize the commitment scheme by generating random points
    Returns:
        g_points: List of n generator points for message elements
        h_point: Single generator point for the blinding factor
    """
    g_points = generate_points(G1, n)
    h_point = generate_points(G1, 1)[0]
    return g_points, h_point


g_points, h_point = setup(n)
print("g_points:", g_points)
print("h_point:", h_point)


def commit_unblinded(message, g_points):
    """
    Create an unblinded commitment to a message
    Args:
        message: List of elements to commit to (must be of length <= n)
        g_points: List of n generator points
    Returns:
        commitment: Point on curve representing the commitment
    """

    # Check that the message is of length less than n
    if len(message) > n:
        raise ValueError("Message must be of length <= n")

    commitment = None
    for i in range(len(message)):
        # Compute sum(message[i] * g_points[i])
        commitment = add(commitment, multiply(g_points[i], message[i]))
    return commitment


# Message to commit to
message = [1, 2, 3, 4, 5, 6, 7, 8, 9]

commitment = commit_unblinded(message, g_points)
print("commitment:", commitment)


### Open the unblinded commitment
def open_unblinded(commitment, message, g_points):
    """
    Verify an unblinded commitment by recomputing it from the provided message
    Args:
        commitment: The original commitment point on the curve to verify against
        message: List of elements that were committed to
        g_points: List of generator points used in the commitment
    Returns:
        bool: True if the recomputed commitment matches the original, False otherwise
    """
    # Recompute the commitment using the same process as commit_unblinded
    commitment_recalc = None
    for i in range(len(message)):
        # Compute sum(message[i] * g_points[i])
        commitment_recalc = add(commitment_recalc, multiply(g_points[i], message[i]))
    # Compare the recomputed commitment with the original
    return commitment_recalc == commitment


assert open_unblinded(commitment, message, g_points)


### Commit to the message with a blinding factor
def commit_blinded(message, g_points, h_point):
    """
    Create a blinded commitment to a message
    Args:
        message: List of elements to commit to (must be of length <= n)
        g_points: List of n generator points
        h_point: Generator point for blinding factor
    Returns:
        commitment_blinded: Point on curve representing the blinded commitment
        blinding_factor: Random value used for blinding
    """

    # Message must be of length <= n
    if len(message) > n:
        raise ValueError("Message must be of length <= n")

    # First compute unblinded commitment
    commitment = None
    for i in range(len(message)):
        commitment = add(commitment, multiply(g_points[i], message[i]))

    # Add randomness through blinding factor
    blinding_factor = random.randint(1, field_modulus)
    commitment_blinded = add(commitment, multiply(h_point, blinding_factor))

    return commitment_blinded, blinding_factor


commitment_blinded, blinding_factor = commit_blinded(message, g_points, h_point)
print("commitment_blinded:", commitment_blinded)
print("blinding_factor:", blinding_factor)


### Open the blinded commitment
def open_blinded(commitment_blinded, message, g_points, blinding_factor, h_point):
    """
    Verify a blinded commitment
    Args:
        commitment_blinded: The commitment to verify
        message: The claimed message
        g_points: List of generator points
        blinding_factor: The random value used to blind the commitment
        h_point: Generator point for blinding factor
    Returns:
        bool: True if commitment is valid, False otherwise
    """
    # Recompute the commitment
    commitment_recalc = None
    for i in range(len(message)):
        commitment_recalc = add(commitment_recalc, multiply(g_points[i], message[i]))

    # Add randomness through blinding factor
    commitment_blinded_recalc = add(
        commitment_recalc, multiply(h_point, blinding_factor)
    )

    return commitment_blinded_recalc == commitment_blinded


assert open_blinded(commitment_blinded, message, g_points, blinding_factor, h_point)
