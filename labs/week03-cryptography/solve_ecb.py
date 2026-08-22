from Crypto.Cipher import AES
import binascii

# 1. ใส่ Key ที่เราเจอจากโค้ด
key = b"0123456789abcdef" 

# 2. Ciphertext จากหน้าเว็บ
hex_ct = "59201843a93540dcbc9bef92370a12a5c4824b6f34cdec589748f5bd08761a23"
ct = binascii.unhexlify(hex_ct)

# 3. สร้างตัวถอดรหัสโหมด ECB
cipher = AES.new(key, AES.MODE_ECB)

# 4. ถอดรหัสและปริ้นผลลัพธ์
plaintext = cipher.decrypt(ct)

print("🎯 Mission accomplished! Your flag is:")
print(plaintext.decode('utf-8', errors='ignore'))