from typing import TYPE_CHECKING
import pytest
from src.ch_2_elgamal import ElGamal

if TYPE_CHECKING:
    from pytest_mock import MockerFixture


def test_key_generation() -> None:
    """Test that key generation produces valid keys with correct properties."""
    elgamal = ElGamal()
    public_key, private_key = elgamal.generate_keys()
    p, g, y = public_key

    assert p > 0
    assert g > 0
    assert y > 0
    assert private_key > 0
    assert pow(g, private_key, p) == y


def test_encryption_decryption() -> None:
    """Test that encryption followed by decryption returns the original message."""
    elgamal = ElGamal()
    public_key, private_key = elgamal.generate_keys()

    original_message = "Hello, World!"
    ciphertext = elgamal.encrypt(original_message, public_key)
    decrypted_message = elgamal.decrypt(ciphertext, private_key)

    assert decrypted_message == original_message


def test_empty_string() -> None:
    """Test encryption and decryption of an empty string."""
    elgamal = ElGamal()
    public_key, private_key = elgamal.generate_keys()

    plain_text = ""
    ciphertext = elgamal.encrypt(plain_text, public_key)
    decrypted_message = elgamal.decrypt(ciphertext, private_key, output_bytes=False)

    assert decrypted_message == plain_text


def test_special_characters() -> None:
    """Test encryption and decryption with special characters."""
    elgamal = ElGamal()
    public_key, private_key = elgamal.generate_keys()

    test_messages = [
        "Hello! @#$%^&*()",
        "Unicode ♠♣♥♦",
        "Numbers 123456789",
        "Newlines\n\rand\ttabs",
    ]

    for message in test_messages:
        ciphertext = elgamal.encrypt(message, public_key)
        decrypted = elgamal.decrypt(ciphertext, private_key, output_bytes=False)
        assert decrypted == message


def test_long_message() -> None:
    """Test encryption and decryption of a long message."""
    elgamal = ElGamal()
    public_key, private_key = elgamal.generate_keys()

    # Create a message of just less than 384 bits long
    message = "a" * (384 // 8 - 1)

    ciphertext = elgamal.encrypt(message, public_key)
    decrypted = elgamal.decrypt(ciphertext, private_key)

    assert decrypted == message
