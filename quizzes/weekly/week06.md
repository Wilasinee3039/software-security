# Weekly Quiz — Week 6 (Authentication & Access Control)

**~10 min · in-class · 6 questions · low-stakes** (drop lowest). No devices / locked browser.

**Name:** Wilasinee Mangkorn  **Student ID:** 6631503039

## MCQ (5 × 1)
1. **IDOR** (broken object-level authorization) is:
   b) reaching another user's object by changing an id
2. The JWT `alg: none` attack works when the server:
   b) accepts an unsigned token as valid
3. Access-control checks must be enforced:
   b) server-side, on every request
4. The OWASP 2025 category covering IDOR is:
   a) A01 Broken Access Control
5. A password-reset token should be:
   c) random, single-use, and expiring

## Short answer — 🔒 your own work (1 × 3)
6. From the **IDOR Treasure Hunt**, which **object id** let you reach another user's data, and what **server-side check** would stop it? Then paste your **personal flag** (`FLAG{...}`) captured from the challenge.

- In the IDOR Treasure Hunt activity, changing the object ID value from **1 to 2** allowed access to another user's data. The vulnerable application displayed Bob's order information because the system only verified whether the user was authenticated, without checking if the user actually owned the object in question.

The issue can be prevented by adding a server-side ownership check before returning the object:

```python
if order["owner"] != user:
    return jsonify(error="forbidden"), 403
```
- Personal flag:
N/A (No personal flag was issued for this lab)
