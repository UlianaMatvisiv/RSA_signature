"""Creating imports for LSB steganography functions"""
import struct
import random
import hashlib
import numpy as np
from crypto import xor_crypt
def generate_pixel_sequence(image_shape, seed_modifier=None):
    """
    Generates a pseudorandom sequence with variable steps between pixels
    """
    height, width, _ = image_shape
    image_info = f"{height}x{width}".encode()
    if seed_modifier:
        image_info += seed_modifier.encode()

    seed = int.from_bytes(hashlib.sha256(image_info).digest()[:4], 'big') % (2**32 - 1)
    rng = np.random.default_rng(seed)

    total_pixels = height * width
    step_seed = int.from_bytes(hashlib.sha256(image_info + b"steps").digest()[:4], 'big')
    step_rng = np.random.default_rng(step_seed)

    steps = step_rng.integers(1, 6, size=total_pixels)
    indices = []
    current_pos = rng.integers(0, total_pixels)

    for _ in range(min(total_pixels, 10_000)):
        indices.append(current_pos)
        current_pos = (current_pos + steps[current_pos]) % total_pixels

        # 10% chance to jump
        if rng.random() < 0.1:
            current_pos = (current_pos + rng.integers(10, 50)) % total_pixels

    # Dedupe while preserving order
    unique = []
    seen = set()
    for idx in indices:
        if idx not in seen:
            unique.append(idx)
            seen.add(idx)
    return [(i // width, i % width) for i in unique]

def create_clean_image(image_array, n_bits):
    """
    Creates a copy of the image with clean LSBs where the signature will be embedded
    """
    clean_image = image_array.copy()
    embed_positions = generate_pixel_sequence(image_array.shape, "signature_embedding")

    # Calculate how many pixels we need
    needed_pixels = (n_bits + 2) // 3  # Add a safety margin
    if needed_pixels > len(embed_positions):
        needed_pixels = len(embed_positions)

    # Clear LSBs in the needed pixels
    for i in range(needed_pixels):
        y, x = embed_positions[i]
        # Clear LSB in each channel (R,G,B)
        clean_image[y, x, 0] &= 0xFE
        clean_image[y, x, 1] &= 0xFE
        clean_image[y, x, 2] &= 0xFE

    return clean_image
def embed_signature(image_array, signature, seed_key):
    """
    Embeds the signature into the image using LSB steganography
    """
    # Create a copy for modification
    stego_image = image_array.copy()

    # Encrypt the signature using XOR
    encrypted_signature = xor_crypt(signature, seed_key)
    data_to_embed = struct.pack("!I", len(encrypted_signature)) + encrypted_signature
    data_bits = []

    # Convert bytes to bits
    for byte in data_to_embed:
        # Format to 8 bits, with leading zeros if needed
        bits = [(byte >> i) & 1 for i in range(7, -1, -1)]
        data_bits.extend(bits)

    embed_positions = generate_pixel_sequence(image_array.shape, "signature_embedding")

    # Check if enough space in image
    if len(embed_positions) * 3 < len(data_bits):
        raise ValueError(f"Image too small for signature embedding.\
                         Need {len(data_bits)} bits, have {len(embed_positions) * 3}")

    # Embed signature bits
    for i, bit in enumerate(data_bits):
        if i // 3 >= len(embed_positions):
            break

        y, x = embed_positions[i // 3]
        channel = i % 3

        # Clear LSB and set new value
        stego_image[y, x, channel] &= 0xFE
        if bit == 1:
            stego_image[y, x, channel] |= 1

    return stego_image
def extract_signature(image_array, seed_key):
    """
    EXTracts the signature from the image
    """
    extract_positions = generate_pixel_sequence(image_array.shape, "signature_embedding")

    # First Extract length (4 bytes = 32 bits)
    length_bits = []
    for i in range(32):
        if i // 3 >= len(extract_positions):
            return None

        y, x = extract_positions[i // 3]
        channel = i % 3
        bit = image_array[y, x, channel] & 1
        length_bits.append(bit)

    # Convert bits to length
    length_bytes = bytearray(4)
    for i in range(4):
        for j in range(8):
            if length_bits[i * 8 + j]:
                length_bytes[i] |= (1 << (7 - j))

    signature_length = struct.unpack("!I", length_bytes)[0]

    # Validate signature length
    if signature_length > 1024 or signature_length < 10:
        print(f"Suspicious signature length detected: {signature_length}")
        return None

    signature_bits = []
    for i in range(32, 32 + signature_length * 8):
        if i // 3 >= len(extract_positions):
            print("Not enough data in image for signature EXTraction")
            return None

        y, x = extract_positions[i // 3]
        channel = i % 3
        bit = image_array[y, x, channel] & 1
        signature_bits.append(bit)

    signature_bytes = bytearray(signature_length)
    for i in range(signature_length):
        for j in range(8):
            idx = i * 8 + j
            if idx < len(signature_bits) and signature_bits[idx]:
                signature_bytes[i] |= (1 << (7 - j))

    decrypted_signature = xor_crypt(signature_bytes, seed_key)
    print(f"EXTracted signature of length {len(decrypted_signature)} bytes")
    print(f"Decrypted signature (first 10 bytes): {decrypted_signature[:10].hex()}")

    return decrypted_signature
def get_clean_image_for_verification(image_array):
    """
    Recreates the original image by clearing LSBs where signature was embedded
    """
    extract_positions = generate_pixel_sequence(image_array.shape, "signature_embedding")

    # Get length from first 32 bits
    length_bits = []
    for i in range(32):
        if i // 3 >= len(extract_positions):
            return None

        y, x = extract_positions[i // 3]
        channel = i % 3
        bit = image_array[y, x, channel] & 1
        length_bits.append(bit)

    # Convert bits to length
    length_bytes = bytearray(4)
    for i in range(4):
        for j in range(8):
            if length_bits[i * 8 + j]:
                length_bytes[i] |= (1 << (7 - j))

    signature_length = struct.unpack("!I", length_bytes)[0]

    # Create clean image by clearing LSBs
    clean_image = image_array.copy()
    total_bits = 32 + signature_length * 8

    # Clear all LSBs used for signature
    for i in range(total_bits):
        if i // 3 >= len(extract_positions):
            break

        y, x = extract_positions[i // 3]
        channel = i % 3
        # Always clear LSB to 0 to match original state
        clean_image[y, x, channel] &= 0xFE

    return clean_image

def add_fake_signature_markers(image_path):
    """
    Adds fake signature markers at the end of the file to confuse analysts
    """
    with open(image_path, 'ab') as f:
        # Generate fake signature patterns that look like RSA signatures
        fake_markers_count = random.randint(2, 5)

        for _ in range(fake_markers_count):
            # Random marker size between 256-512 bytes
            marker_size = random.randint(256, 512)
            fake_data = bytearray(marker_size)

            # Fill with random data
            for i in range(marker_size):
                fake_data[i] = random.randint(0, 255)

            # Add some signature-like patterns
            fake_data[0:8] = b'SIG\x00RSA\x00'  # Fake header

            # Add a plausible structure
            fake_data[8:12] = struct.pack("!I", marker_size - 12)  # Fake length

            f.write(fake_data)

        # Add a final marker that makes it look like a common signature format
        f.write(b'\x00SIGNATURE_END\x00')
