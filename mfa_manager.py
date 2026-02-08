import pyotp
import qrcode
import io
import base64
import secrets
import string
import hashlib

class MFAManager:
    def __init__(self, issuer_name="Kryox"):
        self.issuer_name = issuer_name

    def generate_secret(self):
        """Generate a new base32 TOTP secret"""
        return pyotp.random_base32()

    def get_provisioning_uri(self, username, secret):
        """Generate the otpauth URI for QR codes"""
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, 
            issuer_name=self.issuer_name
        )

    def generate_qr_base64(self, uri):
        """Generate a base64 encoded QR code image from a URI"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode()

    def verify_token(self, secret, token):
        """Verify a 6-digit TOTP token"""
        totp = pyotp.totp.TOTP(secret)
        return totp.verify(token)

    def generate_backup_codes(self, count=8):
        """Generate a list of secure random backup codes"""
        codes = []
        for _ in range(count):
            # 10 character alphanumeric codes
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(10))
            codes.append(code)
        return codes

    def hash_code(self, code):
        """Hash a backup code for secure storage"""
        return hashlib.sha256(code.encode()).hexdigest()

mfa_manager = MFAManager()
