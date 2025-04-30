"""Imports"""
import os
import rsa_keygen
import io_utils
def main():
    """Function to help run image signing and verification"""
    print("Welcome to the Image Signer and Verifier Tool\n")
    # Step 1: Key Generation (if needed)
    generate_keys = input("Do you need to generate RSA keys? (y/n):").strip().lower()
    if generate_keys == 'y':
        private_key_path, public_key_path = rsa_keygen.generate_rsa_keys()
    else:
        private_key_path = input("Enter the path to your private key" \
            "(e.g., keys/private_key.pem): ").strip()
        if not os.path.exists(private_key_path):
            print(f"Error: The private key at {private_key_path} does not exist.")
            return
        public_key_path = input("Enter the path to your public key" \
            "(e.g., keys/public_key.pem): ").strip()
        if not os.path.exists(public_key_path):
            print(f"Error: The public key at {public_key_path} does not exist.")
            return

    # Step 2: Sign the image

    sign_image = input("\nDo you want to sign the image? (y/n): ").strip().lower()
    if sign_image == 'y':
        image_path = input("Enter the path to the image you want to sign: ").strip()
        if not os.path.exists(image_path):
            print(f"Error: The image at {image_path} does not exist.")
            return
        signed_image_path = io_utils.sign_image(image_path, private_key_path)

    # Step 3: Verify the signature
    verify_signature = input("\nDo you want to verify the " \
        "signature of a signed image? (y/n): ").strip().lower()
    if verify_signature == 'y':
        signed_image_path = input("Enter the path to the signed image: ").strip()
        if not os.path.exists(signed_image_path):
            print(f"Error: The signed image at {signed_image_path} does not exist.")
            return

        signature_valid = io_utils.verify_image(signed_image_path, public_key_path)
        if signature_valid:
            print("✅ Signature is valid. Image has not been modified after signing.")

    print("Process completed!")

if __name__ == "__main__":
    main()
