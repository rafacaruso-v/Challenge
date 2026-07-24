from cryptography.fernet import Fernet
import os

def _get_fernet():
    key = os.environ.get("CREDENTIALS_ENCRYPTION_KEY")
    if not key:
        raise ValueError("CREDENTIALS_ENCRYPTION_KEY não definida no .env")
    return Fernet(key.encode())

def encrypt_value(value: str) -> str:
    if not value:
        return ""
    return _get_fernet().encrypt(value.encode()).decode()

def decrypt_value(token: str) -> str:
    if not token:
        return ""
    return _get_fernet().decrypt(token.encode()).decode()