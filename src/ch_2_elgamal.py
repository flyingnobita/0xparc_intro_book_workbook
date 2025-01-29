from typing import Tuple, Optional, Union
import random


class ElGamal:
    """Implementation of the ElGamal cryptosystem using 128-bit prime numbers.

    This implementation provides basic encryption and decryption operations
    using the ElGamal public-key cryptosystem. Key generation is restricted
    to 128-bit prime numbers for practical purposes.
    """

    def __init__(self) -> None:
        """Initialize ElGamal cryptosystem."""
        self.p: int = 0  # Prime modulus
        self.g: int = 0  # Generator
        self.y: int = 0  # Public key
        self.x: int = 0  # Private key

    def generate_prime(self, bits: int = 384) -> int:
        """Generate a prime number of specified bits using Miller-Rabin primality test.

        Args:
            bits: Number of bits for the prime number. Defaults to 384.

        Returns:
            A probable prime number of the specified bit length.
        """

        def is_prime(n: int, k: int = 5) -> bool:
            if n == 2 or n == 3:
                return True
            if n < 2 or n % 2 == 0:
                return False

            r, s = 0, n - 1
            while s % 2 == 0:
                r += 1
                s //= 2

            for _ in range(k):
                a = random.randrange(2, n - 1)
                x = pow(a, s, n)
                if x == 1 or x == n - 1:
                    continue
                for _ in range(r - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
            return True

        while True:
            candidate = random.getrandbits(bits)
            if is_prime(candidate):
                self.p = candidate
                return candidate

    def find_generator(self, p: int) -> int:
        """Find a generator for the multiplicative group modulo p.
        A generator is an element that can generate all elements in the group through exponentiation

        Args:
            p: Prime modulus.

        Returns:
            A generator for the multiplicative group.
        """
        if p == 2:
            return 1

        factors = [2, (p - 1) // 2]
        while True:
            g = random.randrange(2, p)
            # Uses the fact that for a prime p, if g^((p-1)/q) ≠ 1 mod p for all prime factors q of p-1, then g is a generator
            if all(pow(g, (p - 1) // factor, p) != 1 for factor in factors):
                self.g = g
                return g

    def generate_keys(self) -> Tuple[Tuple[int, int, int], int]:
        """Generate public and private keys.

        Returns:
            A tuple containing:
                - Public key components (p, g, y)
                - Private key x
        """
        self.p = self.generate_prime()
        self.g = self.find_generator(self.p)
        self.x = random.randrange(2, self.p - 1)
        self.y = pow(self.g, self.x, self.p)
        return (self.p, self.g, self.y), self.x

    def generate_keys_from_prime(
        self, p: int, g: int
    ) -> Tuple[Tuple[int, int, int], int]:
        self.p = p
        self.g = g
        self.x = random.randrange(2, self.p - 1)
        self.y = pow(self.g, self.x, self.p)
        return (self.p, self.g, self.y), self.x

    def generate_public_key(self, x: int) -> Tuple[int, int, int]:
        return (self.p, self.g, pow(self.g, x, self.p))

    def encrypt(
        self,
        message: Union[str, bytes],
        public_key: Optional[Tuple[int, int, int]] = None,
    ) -> list[Tuple[int, int]]:
        """Encrypt a message using ElGamal encryption.

        Args:
            message: Message to encrypt, can be either string or bytes.
            public_key: Optional tuple of (p, g, y). If None, uses internal values.
            output_bytes: If True, treats input as raw bytes. If False, treats input as string.

        Returns:
            List of tuples, each containing two ciphertext components (c1, c2) for each byte.

        Raises:
            ValueError: If any byte value is larger than the prime modulus.
            TypeError: If message is neither string nor bytes.
        """
        if public_key is None:
            p, g, y = self.p, self.g, self.y
        else:
            p, g, y = public_key

        # Handle input based on type
        if isinstance(message, str):
            message_bytes = message.encode("utf-8")
        elif isinstance(message, bytes):
            message_bytes = message
        else:
            raise TypeError("Message must be either string or bytes")

        # Convert bytes to a single integer for encryption
        message_int = int.from_bytes(message_bytes, "big")
        if message_int >= p:
            raise ValueError("Message value must be smaller than prime modulus")

        k = random.randrange(2, p - 1)
        c1 = pow(g, k, p)
        c2 = (message_int * pow(y, k, p)) % p

        return [(c1, c2)]

    def decrypt(
        self,
        ciphertext: list[Tuple[int, int]],
        private_key: int,
        output_bytes: bool = False,
    ) -> Union[str, bytes]:
        """Decrypt a ciphertext using ElGamal decryption.

        Args:
            ciphertext: List of tuples, each (c1, c2) representing an encrypted message.
            private_key: Private key x for decryption.
            output_bytes: If True, returns raw bytes. If False, attempts UTF-8 decode.

        Returns:
            Decrypted message as either string or bytes.

        Raises:
            UnicodeDecodeError: If output_bytes is False and the decrypted bytes are not valid UTF-8.
        """
        x = private_key

        c1, c2 = ciphertext[0]

        s = pow(c1, x, self.p)
        s_inverse = pow(s, -1, self.p)
        m = (c2 * s_inverse) % self.p

        # Convert the integer back to bytes
        byte_length = (m.bit_length() + 7) // 8
        message_bytes = m.to_bytes(byte_length, "big")

        if output_bytes:
            return message_bytes
        try:
            return message_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # If decoding fails, return as hex string instead
            return message_bytes.hex()
