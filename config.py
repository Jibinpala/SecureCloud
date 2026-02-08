import os
from dotenv import load_dotenv

load_dotenv()

# Cryptographic Key for File & PII Encryption
# Check environment first, then local file
crypto_env = os.getenv("CRYPTO_KEY")
if crypto_env:
    CRYPTO_KEY = crypto_env.encode()
else:
    KEY_FILE = os.getenv("KEY_FILE", "secret.key")
    if not os.path.exists(KEY_FILE):
        from cryptography.fernet import Fernet
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        CRYPTO_KEY = f.read()

# Flask Secret Key
SECRET_KEY = os.getenv("SECRET_KEY", "kryox_enterprise_secure_persistent_key_2026")

# EMAIL CONFIG
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "yourmail@gmail.com")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "gmail_app_password")

MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "3"))

