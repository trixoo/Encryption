# encryption_script.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import re

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(message: str, password: str) -> str:
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return urlsafe_b64encode(salt + iv + encrypted_message).decode()

def decrypt(encrypted_message: str, password: str) -> str:
    encrypted_data = urlsafe_b64decode(encrypted_message.encode())
    salt, iv, encrypted_message = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted_message) + decryptor.finalize()).decode()

def is_strong_password(password: str) -> bool:
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def get_secure_password():
    while True:
        password = input("Enter the password (min 12 chars, including upper, lower, digit, special char): ").strip()
        if is_strong_password(password):
            confirm_password = input("Confirm the password: ").strip()
            if password == confirm_password:
                return password
            else:
                print("Passwords do not match. Try again.")
        else:
            print("Password is not strong enough. Try again.")

def save_to_file(filename, data):
    with open(filename, 'w') as file:
        file.write(data)
    print(f"Output saved to {filename}")

if __name__ == "__main__":
    choice = input("Do you want to (E)ncrypt or (D)ecrypt a message? ").strip().lower()
    if choice == 'e':
        message = input("Enter the message to encrypt: ").strip()
        password = get_secure_password()
        encrypted = encrypt(message, password)
        save_to_file("encrypted_message.txt", encrypted)
    elif choice == 'd':
        encrypted_message = input("Enter the message to decrypt: ").strip()
        password = input("Enter the password: ").strip()
        try:
            decrypted = decrypt(encrypted_message, password)
            save_to_file("decrypted_message.txt", decrypted)
        except Exception as e:
            print("Failed to decrypt the message. Check your password and the encrypted message.")
    else:
        print("Invalid choice. Please choose 'E' for encryption or 'D' for decryption.")
