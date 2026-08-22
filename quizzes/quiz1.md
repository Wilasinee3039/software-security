# Quiz 1 — Foundations & Web Security (Weeks 1–6)

**Course:** Software Security (KOSEN69) · **Time:** 30 min · **Total:** 25 pts
**Covers:** Threat modeling · SDLC/tooling/fuzzing · Cryptography · Injection · XSS · Auth & access control

> Closed book unless your instructor says otherwise.

**Name:** ____________________  **Student ID:** ____________  **Date:** ________

---

## Part A — Multiple Choice (10 × 1 pt)

1. The "I" in **STRIDE** maps to which CIA property?
   a) Integrity b) Confidentiality c) Availability d) Authentication

2. Which is the **most reliable** fix for SQL injection?
   a) Escaping quotes b) A WAF c) Parameterized queries d) Hiding error messages

3. **ECB mode** is insecure mainly because:
   a) it's slow b) identical plaintext blocks produce identical ciphertext c) it needs no key d) it can't be decrypted

4. Which tool type analyzes **source code without running it**?
   a) DAST b) SAST c) IAST d) Fuzzing

5. A payload `<img src=x onerror=alert(1)>` stored in a comment and shown to other users is:
   a) Reflected XSS b) DOM XSS c) Stored XSS d) CSRF

6. Accepting a JWT with header `{"alg":"none"}` is an example of:
   a) CWE-89 b) broken signature verification (CWE-347) c) CWE-79 d) weak hashing

7. Changing `/api/orders/1001` to `/api/orders/1002` and seeing another user's order is:
   a) SQLi b) IDOR / broken access control c) XSS d) CSRF

8. The **best** way to store user passwords is:
   a) MD5 b) SHA-256 c) Base64 d) a salted slow KDF (argon2id/bcrypt)

9. **Coverage-guided fuzzing** primarily finds bugs by:
   a) reading code comments b) mutating inputs and watching for new paths/crashes c) scanning dependencies d) signing artifacts

10. "Allow-list" input validation means:
    a) block known-bad input b) accept only known-good input c) allow everything d) log all input

---

## Part B — Short Answer (3 × 3 pts)

11. Define a **trust boundary** and give one example from a web app.

12. Why is **output encoding** context-dependent (HTML vs attribute vs JS)? Give one consequence of getting it wrong.

13. Explain the difference between **authentication** and **authorization**, and name one vulnerability class for each.

---

## Part C — Spot the Vulnerability (2 × 3 pts)

14. Identify the flaw and give the fix:
```python
q = "SELECT * FROM users WHERE name = '" + request.args["name"] + "'"
db.execute(q)
```

15. Identify the flaw and give the fix:
```python
token = jwt.decode(t, options={"verify_signature": False})
if token["role"] == "admin": grant_access()
```
