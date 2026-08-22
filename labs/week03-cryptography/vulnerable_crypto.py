"""
Week 3 — examples of crypto MISUSE. Your task: exploit, then fix (see solution_skeleton.py).
"""
import hashlib, random
from Crypto.Cipher import AES  # pip install pycryptodome

# MISUSE 1: weak hash, no salt (CWE-916/327)
def store_password(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()

# MISUSE 2: ECB mode — identical plaintext blocks -> identical ciphertext (CWE-327)
HARDCODED_KEY = b"0123456789abcdef"  # MISUSE 3: hardcoded key (CWE-798)
def encrypt_ecb(data: bytes) -> bytes:
    cipher = AES.new(HARDCODED_KEY, AES.MODE_ECB)
    pad = 16 - (len(data) % 16)
    return cipher.encrypt(data + bytes([pad]) * pad)

# MISUSE 4: predictable token (CWE-330: non-CSPRNG)
def reset_token() -> str:
    return "".join(random.choice("0123456789") for _ in range(6))

if __name__ == "__main__":
    print("md5:", store_password("password123"))
    # Notice identical 16-byte blocks produce identical ciphertext blocks:
    print("ecb:", encrypt_ecb(b"A"*16 + b"A"*16).hex())
    print("token:", reset_token())
