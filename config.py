import os
from dotenv import load_dotenv

load_dotenv()

# File System & Database Paths
IS_VERCEL = os.getenv("VERCEL") == "1"
DATABASE_URL = os.getenv("DATABASE_URL") # PostgreSQL connection string

if IS_VERCEL:
    DATABASE_PATH = "/tmp/users.db"
    UPLOAD_FOLDER = "/tmp/uploads"
    KEY_FILE = "/tmp/secret.key"
else:
    DATABASE_PATH = os.getenv("DATABASE_PATH", "database/users.db")
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "encrypted_files/users")
    KEY_FILE = os.getenv("KEY_FILE", "secret.key")

# Cloud Storage Credentials (Optional)
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET")
AWS_S3_REGION = os.getenv("AWS_S3_REGION", "ap-southeast-2")

# Construct Supabase S3 endpoint if project ID is in DATABASE_URL
aws_endpoint_env = os.getenv("AWS_S3_ENDPOINT")
if not aws_endpoint_env and DATABASE_URL and "supabase.co" in DATABASE_URL:
    try:
        # Standard: postgres://...[PROJECT_ID].supabase.co
        # Pooler: postgres.[PROJECT_ID]@... or db.[PROJECT_ID].pooler...
        project_id = None
        if "@" in DATABASE_URL:
            # Check the user part (pooler usually has project_id here)
            user_part = DATABASE_URL.split('@')[0]
            if "postgres." in user_part:
                project_id = user_part.split('postgres.')[1].split(':')[0]
            
            # If still not found, check the host part
            if not project_id:
                host_part = DATABASE_URL.split('@')[1]
                parts = host_part.split('.')
                # db.project_id.supabase.co
                if parts[0] == "db" and len(parts) > 2:
                    project_id = parts[1]
                # project_id.supabase.co
                elif len(parts) > 2 and parts[1] == "supabase":
                    project_id = parts[0]
        
        if project_id:
            AWS_S3_ENDPOINT = f"https://{project_id}.supabase.co/storage/v1/s3"
            print(f"Constructed S3 Endpoint: {AWS_S3_ENDPOINT}")
        else:
            AWS_S3_ENDPOINT = None
    except Exception as e:
        print(f"Error parsing S3 endpoint: {e}")
        AWS_S3_ENDPOINT = None
else:
    AWS_S3_ENDPOINT = aws_endpoint_env
    if AWS_S3_ENDPOINT:
        print(f"Using S3 Endpoint from environment: {AWS_S3_ENDPOINT}")

# Cryptographic Key for File & PII Encryption
# ... (rest of the file)
# Check environment first, then local file
crypto_env = os.getenv("CRYPTO_KEY")
if crypto_env:
    CRYPTO_KEY = crypto_env.encode()
else:
    if not IS_VERCEL and not os.path.exists(KEY_FILE):
        from cryptography.fernet import Fernet
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            CRYPTO_KEY = f.read()
    else:
        # Fallback for Vercel if no key provided via ENV
        CRYPTO_KEY = b"fS4X2_8YpL2yRk9_example_key_only_for_dev_!!!"

# Flask Secret Key
SECRET_KEY = os.getenv("SECRET_KEY", "kryox_enterprise_secure_persistent_key_2026")

# EMAIL CONFIG
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "yourmail@gmail.com")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "gmail_app_password")

MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "3"))

