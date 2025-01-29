def extend_byte_with_leading_zeros(byte_data, target_length):
    """Extends a byte sequence with leading zeros to a target length.

    Args:
        byte_data: A bytes object of any length.
        target_length: The desired length of the extended byte sequence (default: 16).

    Returns:
        A bytes object of the target length with leading zeros.
    """

    if not isinstance(byte_data, bytes):
        raise TypeError("Input must be a bytes object.")
    if target_length < len(byte_data):
        raise ValueError(
            "Target length must be greater than or equal to the input byte length."
        )

    padding_length = target_length - len(byte_data)
    return b"\x00" * padding_length + byte_data
