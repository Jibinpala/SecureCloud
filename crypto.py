from cryptography.fernet import Fernet
from config import CRYPTO_KEY

cipher = Fernet(CRYPTO_KEY)

def encrypt_file(data: bytes) -> bytes:
    return cipher.encrypt(data)

def decrypt_file(data: bytes) -> bytes:
    return cipher.decrypt(data)
