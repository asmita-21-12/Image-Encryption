from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

# Function to generate a random AES key
def generate_aes_key():
    return os.urandom(32)  # 32 bytes = 256 bits

# Function to encrypt an image
def encrypt_image(input_image_path, encrypted_image_path, key):
    with open(input_image_path, 'rb') as f:
        plaintext = f.read()

    # Generate a random IV
    iv = os.urandom(16)

    # Create an AES CBC cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plaintext to the nearest multiple of AES block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Write the IV and ciphertext to the encrypted image file
    with open(encrypted_image_path, 'wb') as f:
        f.write(iv)
        f.write(ciphertext)

# Function to decrypt an image
def decrypt_image(encrypted_image_path, decrypted_image_path, key):
    with open(encrypted_image_path, 'rb') as f:
        iv = f.read(16)  # Read the IV from the beginning of the file
        ciphertext = f.read()

    # Create an AES CBC cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()

    # Write the decrypted plaintext to the decrypted image file
    with open(decrypted_image_path, 'wb') as f:
        f.write(plaintext)

# Example usage
if __name__ == "__main__":
    # Generate a new AES key (for demonstration purposes)
    key = generate_aes_key()

    input_image_path = 'C:\\Users\\Karan\\Desktop\\5.SEM\\CCIDF\\UNIT 2CASE STUDY'
    encrypted_image_path = 'C:\\Users\\Karan\\PycharmProjects\\Prodigy_internship\\encrypted_image.bin'
    decrypted_image_path = 'C:\\Users\\Karan\\PycharmProjects\\Prodigy_internship\\decrypted_image.png'

    encrypt_image(input_image_path, encrypted_image_path, key)
    decrypt_image(encrypted_image_path, decrypted_image_path, key)



