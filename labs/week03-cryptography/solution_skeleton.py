"""
Week 3 — FIX the misuse here. Fill in the TODOs.
pip install argon2-cffi pycryptodome
"""
import os
from argon2 import PasswordHasher
from Crypto.Cipher import AES

ph = PasswordHasher()

def store_password(pw: str) -> str:
    # FIX: argon2id, salted automatically
    return ph.hash(pw)

def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False

def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    # FIX: authenticated encryption (AES-GCM), random nonce, key from env/KMS
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce, ct, tag

def decrypt_gcm(nonce: bytes, ct: bytes, tag: bytes, key: bytes) -> bytes:
    # เพิ่มฟังก์ชันถอดรหัส สำหรับทดสอบ Round-trip
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def reset_token() -> str:
    # FIX: CSPRNG
    import secrets
    return secrets.token_urlsafe(16)

if __name__ == "__main__":
    key = bytes.fromhex(os.environ.get("ENC_KEY_HEX", os.urandom(32).hex()))
    
    # ทดสอบ Argon2
    h = store_password("password123")
    print("argon2 ok:", verify_password(h, "password123"))
    
    # ทดสอบ GCM Round-trip และ Tampered-fails
    nonce, ct, tag = encrypt_gcm(b"secret", key)
    print("gcm round-trip:", decrypt_gcm(nonce, ct, tag, key) == b"secret")
    
    # แกล้งแก้ข้อมูล 1 Byte เพื่อทดสอบ Tamper
    tampered_ct = bytearray(ct)
    if len(tampered_ct) > 0:
        tampered_ct[0] ^= 1
        
    try:
        decrypt_gcm(nonce, bytes(tampered_ct), tag, key)
    except ValueError as e:
        print(f"Tampered-fails proof: MAC check failed ({e})")
        
    # ทดสอบ Token
    print("token:", reset_token())