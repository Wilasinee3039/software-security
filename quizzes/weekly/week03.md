# Weekly Quiz — Week 3 (Cryptography)

**~10 min · 6 questions · low-stakes** (lowest scores dropped). Individual.

**Name:** Wilasinee Mangkorn  **Student ID:** 6631503039

## MCQ (5 × 1)
### 1. Hashing is:
* **Answer:** c) one-way (not reversible)
* **Explanation:** Hashing is a one-way cryptographic function that transforms data into a fixed-length hash value, which cannot be reversed or decrypted to retrieve the original plaintext (unlike Base64, which is a reversible encoding scheme).

---

### 2. The correct way to store passwords is:
* **Answer:** d) a salted, slow KDF (argon2id/bcrypt)
* **Explanation:** Secure password storage requires a slow Key Derivation Function (KDF) with automatic salting, such as Argon2id or bcrypt, to mitigate GPU-based brute-force and rainbow table attacks.

---

### 3. AES-ECB is weak because:
* **Answer:** b) identical plaintext blocks produce identical ciphertext
* **Explanation:** In ECB (Electronic Codebook) mode, identical blocks of plaintext are encrypted into identical blocks of ciphertext using the same key, which leaks structural patterns and information about the original data.

---

### 4. For security tokens you should use:
* **Answer:** b) a CSPRNG such as `secrets`
* **Explanation:** Security tokens (such as password reset tokens or session IDs) must be generated using a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG), like Python's `secrets` module, to prevent predictability and guessing attacks.

---

### 5. Base64 provides:
* **Answer:** c) encoding only (no protection)
* **Explanation:** Base64 is merely a binary-to-text encoding format used to represent data in an ASCII string format; it provides no confidentiality (encryption) or data integrity (hashing) protections.

---

## Short Answer

### 6. Why does a per-user salt defeat precomputed rainbow-table attacks?
A rainbow table is precalculated for specific hashing algorithms using plain or unsalted inputs. When a unique, random salt is appended to each user's password before hashing, the final hash output becomes completely unique even if two users share the same password. This invalidates precalculated tables because an attacker would need to generate an entirely new rainbow table for every single unique salt, making precomputation computationally impractical.
