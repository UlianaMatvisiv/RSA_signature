"""Creating imports for Image I/O wrappers"""
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import numpy as np
from PIL import Image
from stego import create_clean_image, embed_signature, add_fake_signature_markers, \
        get_clean_image_for_verification, extract_signature
def sign_image(image_path, private_key_path = "keys/private_key.pem",
               output_path='signed_image.png'):
    """Signs the image and embeds the signature"""
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except (ValueError, TypeError, IOError) as e:
        print(f"Error loading private key: {e}")
        return False

    try:
        image = Image.open(image_path)
        image_array = np.array(image)

        # Convert to RGB if needed
        if len(image_array.shape) < 3 or image_array.shape[2] < 3:
            image = image.convert('RGB')
            image_array = np.array(image)
    except FileNotFoundError:
        print("File not found!")
        return False
    except PermissionError:
        print("You do not have permission to open this file!")
        return False
    except IOError:
        print("An I/O error occurred while opening the file!")
        return False

    # Determine how many bits we'll need for a signature
    estimated_signature_size = private_key.key_size // 8

    # Create a clean image with LSBs cleared where we'll embed
    clean_image = create_clean_image(image_array, (estimated_signature_size + 4) * 8)

    # Calculate image hash for signing
    image_hash = hashlib.sha256(clean_image.tobytes()).digest()

    # Sign the hash
    signature = private_key.sign(
        image_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print(f"Created digital signature of length {len(signature)} bytes")
    print(f"Original signature (first 10 bytes): {signature[:10].hex()}")

    # Create a simple seed key for XOR encryption from the hash
    seed_key = int.from_bytes(hashlib.sha256(image_hash).digest()[:4], byteorder='big')

    # Embed signature in image
    stego_image_array = embed_signature(image_array, signature, seed_key)

    stego_image = Image.fromarray(stego_image_array)
    stego_image.save(output_path)

    # Add fake signature markers
    add_fake_signature_markers(output_path)

    print(f"Image successfully signed and saved to {output_path}")
    return True

def verify_image(image_path, public_key_path = "keys/public_key.pem"):
    """Verifies the image signature"""
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except (ValueError, TypeError, IOError) as e:
        print(f"Error loading public key: {e}")
        return False

    try:
        image = Image.open(image_path)
        image_array = np.array(image)

        # Convert to RGB if needed
        if len(image_array.shape) < 3 or image_array.shape[2] < 3:
            image = image.convert('RGB')
            image_array = np.array(image)
    except (FileNotFoundError, PermissionError, IOError):
        print("Error opening image.")
        return False

    try:
        # Get clean image for hash calculation
        clean_image = get_clean_image_for_verification(image_array)
        if clean_image is None:
            print("Could not recreate original image state")
            return False

        # Calculate image hash
        image_hash = hashlib.sha256(clean_image.tobytes()).digest()

        # Create seed key for XOR decryption
        seed_key = int.from_bytes(hashlib.sha256(image_hash).digest()[:4], byteorder='big')

        # Extract signature
        signature = extract_signature(image_array, seed_key)
        if signature is None:
            print("Could not EXTract signature from image")
            return False

        # Verify signature
        try:
            public_key.verify(
                signature,
                image_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            print("Invalid signature. Image may have been modified.")
            return False
    except (InvalidSignature, ValueError, IOError) as e:
        print(f"Verification error: {e}")
        return False
