"""Generating RSA keys"""
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys(key_size=4096, output_dir="keys"):
    """
    Generates a pair of 4096-bit RSA keys and saves them to files.
    
    Args:
        key_size (int): The size of the key in bits
        output_dir (str): Directory to save the keys to
            
    Returns:
        tuple: Paths to the private and public key files
    """
    print(f'Generating {key_size}-bit RSA key pair...')

    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # Get public key
    public_key = private_key.public_key()

    # Create a directory for keys if it does not exist
    os.makedirs(output_dir, exist_ok=True)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write the keys to the files
    private_key_path = os.path.join(output_dir, "private_key.pem")
    public_key_path = os.path.join(output_dir, "public_key.pem")

    with open(private_key_path, 'wb') as f:
        f.write(private_pem)

    with open(public_key_path, 'wb') as f:
        f.write(public_pem)

    print(f'RSA {key_size}-bit key pair successfully generated')
    print(f'Private key saved in: {private_key_path}')
    print(f'The public key is saved in: {public_key_path}')

    return private_key_path, public_key_path

if __name__ == "__main__":
    generate_rsa_keys()
