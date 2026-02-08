"""MFA utility functions"""

from cryptography.fernet import Fernet
import base64
import hashlib
from flask import current_app


def get_cipher():
    """Get Fernet cipher from SECRET_KEY"""
    key = base64.urlsafe_b64encode(
        hashlib.sha256(current_app.config['SECRET_KEY'].encode()).digest()
    )
    return Fernet(key)


def encrypt_secret(secret: str) -> str:
    """Encrypt TOTP secret"""
    cipher = get_cipher()
    return cipher.encrypt(secret.encode()).decode()


def decrypt_secret(encrypted: str) -> str:
    """Decrypt TOTP secret"""
    cipher = get_cipher()
    return cipher.decrypt(encrypted.encode()).decode()


def generate_qr_code(secret: str, username: str, issuer: str = 'IOC Manager') -> str:
    """Generate QR code as base64 data URI"""
    import pyotp
    import qrcode
    from io import BytesIO
    import base64 as b64

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=issuer
    )

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = b64.b64encode(buffered.getvalue()).decode()

    return f"data:image/png;base64,{img_str}"
