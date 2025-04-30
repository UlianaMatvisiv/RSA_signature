"XOR helper"
def xor_crypt(data: bytes, key: int) -> bytes:
    """Simple XOR encryption/decryption"""
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    key_length = len(key_bytes)
    result = bytearray(len(data))

    for i, byte in enumerate(data):
        result[i] = byte ^ key_bytes[i % key_length]

    return bytes(result)
