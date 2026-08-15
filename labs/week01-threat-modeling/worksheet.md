# Worksheet 1 — Security Mindset & Threat Modeling (3 hrs)
Course: Software Security (KOSEN69) · Week 1
Aligned to: OWASP 2025 A06 Insecure Design · CWE-501 (Trust Boundary Violation)
Signature game: "Elevation of Privilege" (Microsoft STRIDE card deck)

Ethics note: This worksheet is for modeling and defensive verification on the provided local lab only. Testing is performed only on the student's own VM/localhost and authorized project environment.

> **Course:** Software Security (KOSEN69) · **Week 1**
> **Aligned to:** OWASP 2025 A06 Insecure Design · CWE-501 (Trust Boundary Violation)
> **Signature game:** "Elevation of Privilege" (Microsoft STRIDE card deck)

> **Ethics note:** This week is *modeling only* — you analyze design, you do **not** attack the app. Run the sample app only on your own VM/localhost. Never apply these techniques to systems you do not own or lack written permission to test.

| Name | Student ID | Date | Group |
|---|---|---|---|
| Wilasinee Mangkorn | 6631503039 | 15/08/2026 | |

## Part 2 — Lecture Questions

**1. Define the CIA triad and give one concrete failure example for each of the three properties.**
The CIA triad stands for Confidentiality, Integrity, and Availability, representing the core pillars of information security. A Confidentiality failure is a data breach leaking user passwords. An Integrity failure is an attacker altering the price of an item in a shopping cart before checkout. An Availability failure is a website crashing and becoming inaccessible due to a DDoS attack.

**2. What is a trust boundary, and why does data crossing one deserve extra scrutiny?**
A trust boundary is a logical line where data moves from a less secure, untrusted environment (like the public internet) into a more trusted system (like your application backend). Data crossing this boundary deserves extra scrutiny because it is controlled by external users; treating all incoming data as potentially malicious and validating it prevents attackers from injecting harmful payloads.

**3. Explain "attack surface." Name two things that increase it in a web app.**
The attack surface is the total sum of all potential entry points or vulnerabilities an attacker could exploit to compromise a system. In a web application, two things that heavily increase the attack surface are adding new unauthenticated API endpoints and integrating outdated third-party dependencies or plugins.

**4. What does each STRIDE letter map to, and which security property does each threat violate?**
STRIDE maps to Spoofing (violates Authentication), Tampering (violates Integrity), and Repudiation (violates Non-repudiation/Auditing). It also covers Information Disclosure (violates Confidentiality), Denial of Service (violates Availability), and Elevation of Privilege (violates Authorization).

**5. What does "Secure by Design" (CISA) mean, and how does it differ from bolting security on after release?**
"Secure by Design" means integrating security principles directly into the software's architecture from the very first planning stages to eliminate entire classes of vulnerabilities. This proactive approach differs fundamentally from "bolting security on," which is a reactive, never-ending cycle of finding and patching individual bugs only after the software has already been deployed to production.

## Part 3 — Hands-on Lab (180 min)
**Learning goals:** build a data-flow diagram (DFD), apply STRIDE to a real Flask app, rank risks, and propose mitigations.
**Prerequisites:** Docker + Docker Compose in your VM; a drawing tool (draw.io / paper + photo); the Elevation of Privilege deck (print or virtual) — free print-and-play PDF at [github.com/adamshostack/eop](https://github.com/adamshostack/eop).

**Environment setup**
```bash
cd labs/week01-threat-modeling
docker compose up --build           # starts sample-app on http://localhost:8080
curl -s -X POST localhost:8080/notes -H 'Content-Type: application/json' \
     -d '{"owner":"alice","body":"hello"}'   # observe behavior, do not attack
curl -s localhost:8080/notes

echo "demo file" > demo.txt
curl -s -X POST localhost:8080/upload -F "file=@demo.txt"   # observe behavior, do not attack
curl -s localhost:8080/files/demo.txt
```

Source to model lives in `sample-app/app.py`. Template to fill: `THREAT-MODEL-TEMPLATE.md` (copy it, do not edit the original).

**What to submit per task:** the threat/element identified + a screenshot (DFD, table, or running app) + a 2–3 sentence mitigation.

**Task 0 — Onboarding (5 min)** · *Goal:* prove the environment works. *Steps:* `docker compose up`, hit `/notes` and `/files/<name>`, read `sample-app/app.py`. *Deliverable:* ![Screenshot of the running app](<Task 0.png>).

**Task 1 — Draw the DFD (25 min)** · *Goal:* map the system. *Steps:* identify the external entity (web client), the process (Flask app), the data store (`notes.db` SQLite), the `uploads/` store, and the flows for `/notes`, `/upload`, `/files/<name>`; mark the Internet→app trust boundary with a dashed line. *Deliverable:* ![DFD image](<Task 1.png>).

**Task 2 — STRIDE the elements (30 min)**
*Deliverable:* Completed STRIDE table.

| Element | S (Spoofing) | T (Tampering) | R (Repudiation) | I (Info Disclosure) | D (Denial of Service) | E (Elevation of Privilege) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Web Client** | Spoof client identity | Manipulate request data | Deny sending request | — | Send excessive requests | Attempt unauthorized actions |
| **Flask App** | No authentication on `/notes` | Raw `f.filename` trusted | No request logging | Save-path disclosure | Upload/resource exhaustion | Unauthorized actions |
| **`notes.db`** | — | Unauthorized note modification | No audit trail | Unauthorized note reading | Database/resource exhaustion | — |
| **`uploads/`** | — | Arbitrary file write via filename | No file-operation logging | Resolved path disclosed | Disk exhaustion | Potential unsafe file placement |

### Task 3 — Elevation of Privilege game

**Carded Threats & Score:**
1. **Card: 4 of Spades (Spoofing)** 
   * *Card text:* "An attacker can anonymously connect, because we expect authentication to be done at a higher level."
   * *Mapped to DFD:* The `/notes` POST endpoint accepts JSON payloads (`owner` and `body`) and writes them directly to `notes.db` without any session validation or authentication checks.
2. **Card: 6 of Clubs (Tampering)**
   * *Card text:* "An attacker can write to a data store your code relies on."
   * *Mapped to DFD:* The `/upload` endpoint uses `os.path.join(UPLOAD_DIR, f.filename)`. By using a payload like `../../../notes.db`, an attacker can overwrite the actual SQLite database file the application relies on.
3. **Card: 10 of Hearts (Information Disclosure)**
   * *Card text:* "An attacker can read information in files or databases with no access controls."
   * *Mapped to DFD:* The `/notes` GET endpoint executes `SELECT id, owner, body FROM notes` and returns all rows to anyone who visits the URL, lacking any authorization constraints.

**Total Score:** 3 points.

### Task 3b — Systems-level pass

*   **Trust boundaries end-to-end:** 
    A request flows from Web Client ➔ (Internet Boundary) ➔ Flask App (`app.py`) ➔ (OS Boundary) ➔ File System (`notes.db` & `uploads/`). The crossing with **no check on it** is the Internet ➔ Flask App boundary for both `/notes` and `/upload` endpoints, as they blindly accept unauthenticated input.
*   **Assume one element is fully owned:**
    1.  *Flask process:* If an attacker owns the running Flask process, they immediately gain read/write access to `notes.db` and the `uploads/` directory, and can execute commands with the same OS privileges as the Python runtime.
    2.  *uploads/ store:* If an attacker completely controls the `uploads/` directory, they can place a malicious `.html` or `.js` file there. Since `/files/<name>` serves these files via `send_from_directory`, the attacker can link it to victims to achieve Stored XSS.
*   **Chain two "low" findings:** 
    Missing file size limits on `/upload` (Minor DoS) ➔ Unauthenticated access to `/upload` (Spoofing/Bypass). 
    **Consequence:** An anonymous attacker can write a simple loop script to rapidly upload gigabytes of dummy files, exhausting the host server's disk space and causing the entire Flask application (and potentially the OS) to crash.
*   **One-line system claim:** 
    "Even if every element-level mitigation in Task 8 is implemented, this system still fails if **the Flask application is run as the 'root' user**, allowing any unforeseen bypass to instantly compromise the entire host operating system."

---


### Task 4 — Abuse cases & attacker personas

**Persona 1: Anonymous Internet Attacker** (Goal: System Disruption & Server Takeover)
*   **Abuse Case 1 (Tampering / Path Traversal):** The attacker bypasses the intended `uploads/` directory by sending a POST request to `/upload` with the filename `../../../app.py` containing a malicious script, overwriting the application's core logic to achieve Remote Code Execution.
*   **Abuse Case 2 (Denial of Service):** The attacker writes a simple script to continuously send unauthenticated POST requests to `/upload` with massive junk files. Since the endpoint lacks file size validation and rate limits, this rapidly exhausts the server's disk space, causing the application to crash.

**Persona 2: Malicious Peer / Troll** (Goal: Defamation & Data Harvesting)
*   **Abuse Case 3 (Spoofing):** The attacker sends a POST request to `/notes` specifying `{"owner": "admin", "body": "offensive content"}`. Because the endpoint explicitly trusts the `owner` field without any authentication checks, the attacker successfully injects fake records to ruin another user's reputation.
*   **Abuse Case 4 (Information Disclosure):** The attacker continuously sends GET requests to the `/notes` endpoint. Since the API lacks authorization and returns the entire `notes` database table to any visitor, the attacker successfully scrapes all notes created by all users in the system.

---

### Task 5 — Path-traversal deep-dive**
   **Data Flow Trace:** `/upload` accepts `f.filename` and passes it directly to `os.path.join(UPLOAD_DIR, f.filename)`. If `f.filename` contains `../`, `os.path.join` resolves the relative path segments, causing the target path to escape the intended `uploads/` directory. Conversely, `/files/<name>` utilizes Flask's `send_from_directory()`, which securely normalizes paths and blocks traversal attempts.
    **Secure Design Note:** Using `secure_filename()` neutralizes path traversal components by stripping directory navigation characters.

### Task 6 — Threat-model the project target

![Task 6](notevault-dfd-1.png)

**Top 3 STRIDE Threats for NoteVault:**
1. **Spoofing (No Session Validation):** The `/notes` POST endpoint natively trusts the user identity provided in the request payload without enforcing a cryptographically signed session token, allowing anyone to impersonate any user.
2. **Information Disclosure (Insecure Direct Object Reference - IDOR):** The application fetches note details using predictable, sequential integer IDs in the URL without enforcing ownership authorization checks, allowing an attacker to directly read other users' private notes by incrementing the ID.
3. **Tampering (Stored Cross-Site Scripting):** The note rendering component directly outputs user-supplied note bodies to the browser without applying HTML entity encoding or sanitization, permitting an attacker to store malicious JavaScript that executes when a victim views the note.

---

### Task 7 — Security requirements
1. **Spoofing:** "The system MUST reject any POST request to `/notes` with a 401 Unauthorized status code if the request does not include a valid, signed JWT session token."
2. **Tampering:** "Given a file upload request with the filename `../../../test.txt`, the system MUST save the file strictly within the `uploads/` directory as `test.txt`, stripping all path traversal characters."
3. **Denial of Service:** "The `/upload` endpoint MUST return a 413 Payload Too Large error if the uploaded file exceeds 5MB in size."

   
### Task 8 — Defend / fix it: rank & mitigate 🛡️

**Top 5 Threats Ranked (Likelihood × Impact):**
| Rank | Threat (Element) | Risk | Proposed Mitigation |
| :--- | :--- | :--- | :--- |
| 1 | **Tampering:** Path Traversal on `/upload` | High | Use `secure_filename()` to sanitize input before passing to `os.path.join`. |
| 2 | **Spoofing:** Unauthenticated `/notes` POST | High | Implement strict session token (JWT) validation for all POST requests. |
| 3 | **Information Disclosure:** `/files/<name>` | Medium | Store uploads outside the web root to prevent direct execution/access. |
| 4 | **Denial of Service:** Resource exhaustion on `/upload` | Medium | Enforce strict file size limits (e.g., 5MB max) and IP-based rate limiting. |
| 5 | **Repudiation:** System-wide lack of logging | Low | Centralize application logging to record all state-changing API requests. |

---

**Implemented Evidence & Verification (Path Traversal Fix):**

**1. Commit Verification (`git log` / `git show` proof):**
*   **Commit Hash:** `15743a32e766c118adfb3832b2e6d9b85f3eec4b` (Branch: `wk01`)
*   *Screenshot showing the live git log / commit details with the identity stamp:*
    ![Git Log proof](<Task 8-1.png>)

**2. Code Diff:**
```diff
--- a/sample-app/app.py
+++ b/sample-app/app.py
@@ -35,5 +35,6 @@
-    safe_name = f.filename
+    from werkzeug.utils import secure_filename
+    safe_name = secure_filename(f.filename)
     f.save(os.path.join(UPLOAD_DIR, safe_name))
     return {"saved": safe_name}


## Part 4 — Reflection

1. **Map finding to CWE and OWASP:** 
   The Path Traversal vulnerability in the `/upload` endpoint maps directly to **CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)** and **OWASP A06:2025 (Insecure Design)**, because the application architecturally trusts and processes raw user input for filesystem paths without validation checks.
2. **Real-world breach (Reference & Source):** 
   A prominent real-world example is the Apache HTTP Server path traversal and file disclosure vulnerability (**CVE-2021-41773**), where a flaw in path normalization allowed attackers to map URLs to files outside the expected document root (documented in the NIST National Vulnerability Database at `https://nvd.nist.gov/vuln/detail/CVE-2021-41773`). A strict design-level control enforcing path normalization and root-directory jail confinement would have prevented this flaw.
3. **Best Mitigation:** 
   Implementing `secure_filename()` combined with an extension allowlist provides the most practical risk reduction per unit of effort for this specific endpoint. While it is an instance-level fix rather than a complete elimination of all file-handling logic errors across the entire codebase, it effectively neutralizes user-supplied path manipulation vectors in a single line.

---

## 🤖 Audit the AI (required)
1. **Ask an AI to fix:** *"How do I securely handle file uploads in Python Flask to prevent path traversal?"*
   *AI's answer:* `safe_name = f.filename.replace('../', '')` followed by `f.save(...)`.
2. **What's wrong:** The string replacement method is incomplete and easily bypassed using nested syntax like `....//`, which collapses into a new traversal sequence after replacement.
3. **Correct, verified version & Empirical Test:** 
   Using `werkzeug.utils.secure_filename(f.filename)`. Empirical testing with `../../../etc/hacked.txt` successfully neutralized the payload to `etc_hacked.txt`.

---

## 🧠 Comprehension & Prompt (required)
**A. EiPE:** The vulnerable endpoint blindly concatenates user-supplied filenames into file system paths. Because inputs can contain directory traversal operators (`../`), attackers can escape the intended storage folder and write files to arbitrary locations.
**B. Prompt Problem:** 
*Prompt:* "Write a secure Python Flask upload snippet that completely prevents path traversal without using flawed string replacement, leveraging framework standard sanitization utilities."
*Verified result:* Successfully generated `secure_filename()` implementation, verified via live `curl` testing where malicious traversal paths were successfully stripped and neutralized.