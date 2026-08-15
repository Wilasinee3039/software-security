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

**Task 2 — STRIDE the elements (30 min)** · *Goal:* enumerate threats per element. *Steps:* for each element fill the S/T/R/I/D/E grid. Ground it in real code: `/notes` accepts a client-supplied `owner` with no auth (Spoofing); `/upload` saves raw `f.filename` — arbitrary-file-write (Tampering) — and echoes the resolved save path back in its response (Information disclosure); `/files/<name>` reads it back but is comparatively defended (see Task 5); no logging anywhere (Repudiation). *Deliverable:* completed STRIDE table.

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

### Task 5 — Path-traversal deep-dive
**Data Flow Trace & Explanation:**
The vulnerability lies entirely in `/upload`. When an attacker sends a filename like `../../hacked.txt`, the code uses `os.path.join(UPLOAD_DIR, f.filename)`. Because `os.path.join` resolves `../`, it moves up the directory tree, escaping `uploads/` and writing the file wherever the payload dictates.
Conversely, the `/files/<name>` endpoint is actually protected. It uses Flask's native `send_from_directory()`, which securely normalizes the path and will throw a 404/403 error if an attacker attempts to read files outside the designated `UPLOAD_DIR` using `../`.
**Secure Design Note:** To fix `/upload`, we must sanitize the input using `werkzeug.utils.secure_filename(f.filename)`, which proactively strips slashes and `../` before the path is joined.

### Task 6 — Threat-model the project target

![DFD NoteVault](notevault-dfd.jpg)

**Top 3 STRIDE Threats for NoteVault:**
1. **Spoofing (No Session Validation):** The `/notes` POST endpoint natively trusts the user identity provided in the request payload without enforcing a cryptographically signed session token, allowing anyone to impersonate any user.
2. **Information Disclosure (Insecure Direct Object Reference - IDOR):** The application fetches note details using predictable, sequential integer IDs in the URL without enforcing ownership authorization checks, allowing an attacker to directly read other users' private notes by incrementing the ID.
3. **Tampering (Stored Cross-Site Scripting):** The note rendering component directly outputs user-supplied note bodies to the browser without applying HTML entity encoding or sanitization, permitting an attacker to store malicious JavaScript that executes when a victim views the note.

---

### Task 7 — Security requirements
1. **Spoofing:** "The system MUST reject any POST request to `/notes` with a 401 Unauthorized status code if the request does not include a valid, signed JWT session token."
2. **Tampering:** "Given a file upload request with the filename `../../../test.txt`, the system MUST save the file strictly within the `uploads/` directory as `test.txt`, stripping all path traversal characters."
3. **Denial of Service:** "The `/upload` endpoint MUST return a 413 Payload Too Large error if the uploaded file exceeds 5MB in size."

   
### Task 8 — Defend / fix it: rank & mitigate

**Top 5 Threats Ranked (Likelihood × Impact):**
1. **Tampering / Path Traversal (`/upload`):** High risk. Attacker can write arbitrary files to the server. *Mitigation:* Use `secure_filename()` and validate extensions against an allowlist.
2. **Spoofing (`/notes`):** High risk. Anyone can post as any owner. *Mitigation:* Implement strict authentication (e.g., JWT or Session tokens) for the POST endpoint.
3. **Information Disclosure (`/files/<name>`):** Medium risk. Exposes internal files if traversed. *Mitigation:* Store uploads outside the web root and serve via a secure controller.
4. **Denial of Service (DoS on `/upload`):** Medium risk. Attackers can exhaust disk space. *Mitigation:* Enforce strict file size limits and rate limiting on the upload endpoint.
5. **Repudiation (System-wide):** Low-Medium risk. No actions are logged. *Mitigation:* Implement centralized application logging for all state-changing requests.

**Implemented Mitigation Evidence:**
*   **The diff:** Added `from werkzeug.utils import secure_filename` and wrapped `f.filename` with `secure_filename()` before saving.
*   **Evidence it works:** As shown in the screenshot, the payload `../../../etc/hacked.txt` was successfully neutralized and saved safely as `etc_hacked.txt` within the designated uploads folder.
*   **Class vs. Instance fix:** This is an **instance fix** because it only applies to this specific `/upload` endpoint. A **class fix** would involve a centralized storage module or framework-level middleware that completely prevents any user-supplied string from being used directly in file I/O operations across the entire application without passing through a sanitization pipeline.
![Test fix](<Task 1-1.png>)

## Part 4 — Reflection

1. **Map finding to CWE/OWASP:** The vulnerability maps to **CWE-22 (Path Traversal)** and **OWASP A06 (Insecure Design)** because the application natively trusts user-controlled paths without architectural boundaries.
2. **Real-world breach:** The Apache HTTP Server vulnerability (CVE-2021-41773) allowed path traversal because a logic flaw in path normalization allowed attackers to read files outside the document root. A strict "Secure by Design" mechanism that normalizes paths and enforces a root-jail would have prevented it.
3. **Best Mitigation:** Implementing `secure_filename()` offers the best ROI. It requires only one line of code but completely neutralizes an entire class of path traversal inputs.

---

## 🤖 Audit the AI (required)

**1. Ask an AI to fix:**
*Prompt:* "How do I fix a path traversal vulnerability in Flask file uploads?"
*AI's answer (simulated):* "You can fix it by removing the `../` characters from the filename before saving. Use this code: 
`safe_name = f.filename.replace('../', '')`
`f.save(os.path.join(UPLOAD_DIR, safe_name))`"

**2. Find what's wrong or risky:**
The AI's suggested fix is dangerously incomplete. The line `safe_name = f.filename.replace('../', '')` is vulnerable to bypass using nested payloads like `....//`. When the `replace` function removes the inner `../`, the remaining characters concatenate to form a new `../`, successfully traversing the directory again.

**3. Correct, verified version:**
```python
from werkzeug.utils import secure_filename
safe_name = secure_filename(f.filename)
f.save(os.path.join(UPLOAD_DIR, safe_name))

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*