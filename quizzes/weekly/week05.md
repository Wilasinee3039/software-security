# Weekly Quiz — Week 5 (Cross-Site Scripting)

**~10 min · in-class · 6 questions · low-stakes** (drop lowest). No devices / locked browser.

**Name:** Wilasinee Mangkorn  **Student ID:** 6631503039

## MCQ (5 × 1)
1. Stored XSS differs from reflected XSS because the payload is:

Answer: **b) saved on the server and served to later victims**

---

2. XSS code executes in:

Answer: **c) the victim's browser**

---

3. The primary defense against XSS is:

Answer: **b) context-aware output encoding (+ CSP)**

---

4. The CWE id for XSS is:

Answer: **b) CWE-79**

---

5. The HttpOnly cookie flag helps because it:

Answer: **b) stops JavaScript from reading the cookie**

---

## Short answer — 🔒 your own work (1 × 3)
6. Paste the XSS payload that **scored in this week's XSS Golf** and name the **sink** it reached (e.g., `innerHTML`, attribute, URL). Then paste your personal flag (`FLAG{...}`) captured from the challenge.

Payload:

```html
<script>alert(1)</script>
```

Sink:

HTML context / HTML response sink (`/hello` endpoint), where user input was directly inserted into the HTML page.

Personal flag:

N/A (No personal flag was issued for this lab.)
