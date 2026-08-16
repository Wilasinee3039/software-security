# Worksheet 2 — Secure SDLC & Tooling (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 2**
> **Aligned to:** OWASP 2025 (A05 Injection [CWE-89, CWE-78], A04 Cryptographic Failures [CWE-327], A02 Security Misconfiguration [CWE-798, CWE-489]) · CWE-798, CWE-89, CWE-78, CWE-327, CWE-489
> **Signature game:** "Bug Triage Race" (scan → triage; score = true positives − misclassified)

> **Ethics note:** The scanners run only against the provided `vulnerable-repo/` on your own machine. Do not point SAST/secret scanners at third-party repos or production systems without authorization. Treat any secret you find here as fake lab data.

## Part 1 — Student Information
| Name | Student ID | Date | Group |
|---|---|---|---|
| Wilasinee Mangkorn|6631503039 |16/08/2026 | |

## Part 2 — Lecture Questions

1. **Distinguish SAST, DAST, and SCA — what does each see, and when in the SDLC does each run?**  
   Static Application Security Testing (SAST) analyzes source code during the write phase to find structural code flaws, while Software Composition Analysis (SCA) reviews third-party dependencies during the build phase. In contrast, Dynamic Application Security Testing (DAST) functions as a black-box tester examining the running application during deployment. Each tool targets a different layer and stage of the software development life cycle (SDLC).

2. **What is secret scanning, and why do hardcoded secrets keep ending up in repos?**  
   Secret scanning is an automated process that inspects codebases and commit histories for leaked credentials, API tokens, and passwords. Hardcoded secrets frequently end up in repositories because developers rely on quick local prototyping, debugging shortcuts, or lack strict adherence to secure configuration management practices.

3. **What does "shift-left / DevSecOps" mean in practice for a CI pipeline?**  
   "Shift-left" means moving security checks earlier into the development lifecycle rather than leaving them as a final hurdle before production. In practice for a CI pipeline, this involves automating SAST, SCA, and secret scanning directly into automated build and commit gates.

4. **Why is coverage-guided fuzzing considered the dominant modern bug-finding technique?**  
   Coverage-guided fuzzing automatically mutates inputs and monitors execution paths to discover deep logic bugs and memory-safety crashes that standard static linters miss. Its ability to continuously explore unknown code paths makes it exceptionally effective at finding complex edge-case vulnerabilities.

5. **Define true positive vs. false positive in scanner triage, and why misclassifying both directions is costly.**  
   A true positive is a real, legitimate vulnerability correctly identified by a tool, whereas a false positive is a benign construct incorrectly flagged as a security flaw. Misclassifying true positives leaves critical system vulnerabilities unpatched, while misclassifying false positives wastes engineering time and causes alert fatigue.

![A left to right SDLC pipeline showing SAST at write code, secret scanning at commit, SCA and fuzzing at build, and DAST at deploy, with what each tool cannot see written underneath it.](img/sdlc-gates.svg)

## Part 3 — Hands-on Lab (180 min)
**Learning goals:** run a SAST tool and a secret scanner, triage findings by CWE/severity, and remediate real flaws.
**Prerequisites:** Docker installed; internet to pull the Semgrep/Gitleaks images.

**Environment setup**
```bash
cd labs/week02-sdlc-tooling
cat scan.sh                 # see exactly what it runs
bash scan.sh                # Semgrep (p/default + p/owasp-top-ten) then Gitleaks on ./vulnerable-repo
```
Target under scan: `vulnerable-repo/app.py` (plus `requirements.txt`). It contains five planted flaws.

**What to submit per task:** the command/payload run + a screenshot of the finding + a 2–3 sentence mitigation.

**Task 0 — Onboarding (5 min)** · *Goal:* confirm tooling. *Steps:* run `bash scan.sh`; confirm both Semgrep and Gitleaks sections produce output. *Deliverable:* screenshot showing both tools ran.
![Run cat scan.sh](<Screenshot 2026-08-16 095059.png>)
![Run bash scan.sh](<Screenshot 2026-08-16 095247.png>)


**Task 1 — SAST sweep with Semgrep (25 min)**

* **Secret 1 (AWS Secret Access Key):** Located at `app.py:11`, flagged as CWE-798 (Hardcoded Credentials) via secret scanning.
* **Secret 2 (Database Password):** Located at `app.py:12`, flagged as CWE-798 (Hardcoded Credentials) via secret scanning.
![alt text](<Screenshot 2026-08-16 095936-1.png>)
* **SQL Injection (`/user`):** Located at `app.py:19`, flagged as CWE-89 due to direct string formatting into the SQL query.
![alt text](<Screenshot 2026-08-16 100152-1.png>)
* **OS Command Injection (`/ping`):** Located at `app.py:26`, flagged as CWE-78 due to executing user input with `shell=True`.
![alt text](<Screenshot 2026-08-16 100216-1.png>)
* **Weak Password Hash:** Located at `app.py:30`, flagged as CWE-327 due to using the insecure `hashlib.md5` algorithm.
![alt text](<Screenshot 2026-08-16 100243-1.png>)
* **Debug Mode Enabled:** Located at `app.py:33`, flagged as CWE-489 because Flask runs with `debug=True`.
![alt text](<Screenshot 2026-08-16 100301.png>)

**Task 2 — Secret scan with Gitleaks (15 min)**

* **AWS_SECRET_ACCESS_KEY:** Identified at `app.py:11`, triggering the `generic-api-key` rule (CWE-798).
* **DB_PASSWORD:** Identified at `app.py:12`, triggering the `generic-api-key` rule (CWE-798).
![alt text](<Screenshot 2026-08-16 095936-1.png>)

**Task 3 — Bug Triage Race (30 min)**

| Tool | File:Line | CWE | Severity | TP/FP | Fix idea & Justification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Semgrep | `app.py:19` | CWE-89 | High | TP | **Fix:** Use parameterized queries (`cursor.execute("SELECT * FROM users WHERE name = ?", (name,))`). <br>**Justification:** Direct string formatting allows malicious SQL payloads to manipulate the query structure. |
| Semgrep | `app.py:26` | CWE-78 | High | TP | **Fix:** Remove `shell=True` and pass arguments as a list (`subprocess.run(["ping", "-c", "1", host])`). <br>**Justification:** Passing unvalidated user input directly into a shell execution sink enables command injection. |
| Gitleaks | `app.py:11` | CWE-798 | Critical | TP | **Fix:** Move the API key to environment variables (`os.getenv("AWS_SECRET_ACCESS_KEY")`). <br>**Justification:** Hardcoding secrets in source code files exposes them to unauthorized access if the repository is leaked. |
| Semgrep | `app.py:30` | CWE-327 | Medium | TP | **Fix:** Replace MD5 with an adaptive hashing function like `bcrypt` or `argon2`. <br>**Justification:** MD5 is cryptographically broken and vulnerable to collision and brute-force attacks. |
| Semgrep | `app.py:33` | CWE-489 | Low | FP | **Fix:** Ensure debug mode is toggled dynamically via environment variables (`debug=os.getenv("DEBUG", "False")`). <br>**Justification:** While flagged as a misconfiguration, this specific flag is intended for isolated local testing environments where traceback data is necessary. |

**Task 4 — Fuzzing intro (10 min)**

* **Deliverable (Crash Output):** ![Fuzzing](<Screenshot 2026-08-16 103405.png>)
* **Why Fuzzing Finds This (and SAST doesn't):** Coverage-guided fuzzing dynamically executes the compiled binary with mutated inputs, allowing it to discover runtime memory-safety bugs and edge cases. In contrast, a static linter or SAST tool analyzing this specific 4-line snippet would likely miss the missing bound check because it only evaluates syntax patterns and lacks the dynamic execution context to realize `data[3]` is out of bounds when the input size is exactly 3. Additionally, seeding the corpus with "FUZ" bypasses the unpredictability of randomly guessing magic bytes, drastically accelerating the crash discovery.

**Task 5 — Scan the project target (40 min)**

**Findings List (NoteVault Project):**

* **Tool: Semgrep (Total Findings: 31)**
  * Finding 1: `app.py:134` - [CWE-522] `jwt-python-hardcoded-secret` (Hardcoded JWT secret used for token generation).
  * Finding 2: `app.py:136` - [CWE-614] `secure-set-cookie` (Insecure cookie configuration missing `secure=True`, `httponly=True`, `samesite='Lax'`).
  * Finding 3: `app.py:178` - [CWE-89] `sql-injection-db-cursor-execute` (Directly constructed SQL string formatting vulnerable to SQL Injection).
  * Finding 4: `app.py:202` - [CWE-78] `subprocess-injection` (Dangerous use of `subprocess.run` with `shell=True` allowing command injection).
  * Finding 5: `app.py:209` - [CWE-489] `debug-enabled` (Flask app configured with `debug=True` which can leak sensitive data in production).

* **Tool: Gitleaks**
  * Status: Clean. `no leaks found` in the repository.

* **Tool: Trivy** (Found 32 total vulnerabilities in `requirements.txt`)
  * Finding 1: `Flask / CVE-2023-30861` - [HIGH] Possible disclosure of permanent session cookie due to missing Vary: Cookie.
  * Finding 2: `PyJWT / CVE-2022-29217` - [HIGH] Key confusion through non-blocklisted public key formats.
  * Finding 3: `Werkzeug / CVE-2023-25577` - [HIGH] High resource usage when parsing multipart form data with many fields.
  * Finding 4: `urllib3 / CVE-2021-33503` - [HIGH] ReDoS in the parsing of authority part of URL.

**Task 6 — Build a security CI gate (25 min)**

**Deliverable (Workflow File & Logs):**  
The pre-configured `security-ci.yml` template was successfully activated and executed via GitHub Actions using `workflow_dispatch`.

**Action Output:**  
The attached screenshot demonstrates a failed GitHub Actions security pipeline. Specifically, the **Secret scanning (Gitleaks)** job failed after detecting hardcoded secrets, causing the security CI workflow to report a failure. This demonstrates that the security gate successfully identifies exposed secrets and prevents the workflow from being considered successful when a security violation is detected.

![Failed](<Screenshot 2026-08-16 110512.png>)


**Task 7 — SAST blind spots (20 min)**

**Bug:** Hardcoded credentials/secrets in `app.py`, specifically `AWS_SECRET_ACCESS_KEY` and `DB_PASSWORD`.

Semgrep did not flag these hardcoded secrets because pattern-based SAST rules may not recognize arbitrary credential-like strings, while Gitleaks is specifically designed for secret detection. This demonstrates that SAST coverage depends on the rules being used and should be complemented by dedicated secret-scanning tools.



**Task 8 — Defend / fix it (10 min)** · *Goal:* remediate the planted flaws in `vulnerable-repo/app.py`. *Steps:* rewrite `/user` to use a parameterized query (`?` placeholder); remove `shell=True` and pass an argument list in `/ping`; move both secrets to environment variables; replace `md5` with bcrypt/argon2; set `debug=False`. *Deliverable:* a before/after diff for each fix mapped to its CWE.

### Part 4 — Reflection

**1. Map two of your findings to their CWE and to the matching OWASP category:**
* **Finding 1 (SQL Injection):** Mapped to CWE-89 (Improper Neutralization of Special Elements used in an SQL Command). This aligns directly with the **Injection** category in the OWASP Top 10.
* **Finding 2 (Hardcoded AWS Secret):** Mapped to CWE-798 (Use of Hard-coded Credentials). This aligns with the **Cryptographic Failures** (or Identification and Authentication Failures) category in the OWASP Top 10.

**2. Name a real-world breach caused by a hardcoded/leaked secret or an injection flaw, and what control would have caught it pre-release:**
* **Breach:** In the massive 2016 Uber data breach, developers accidentally left hardcoded AWS access keys in a private GitHub repository. Attackers discovered these keys and used them to access Amazon S3 buckets containing the personal data of 57 million users and drivers.
* **Preventative Control:** This catastrophic breach could have been easily caught pre-release by integrating an automated **Secret Scanning tool (like Gitleaks)** into the CI/CD pipeline or as a strict pre-commit hook. This control would have flagged the AWS keys and blocked the commit from ever reaching the repository.

**3. Which single tool (SAST vs. secret scanning) gave the highest-value findings on this repo, and why?**
* **Highest-Value Tool:** SAST (Semgrep).
* **Why:** While secret scanning is absolutely critical for preventing immediate system takeovers, SAST (Semgrep) delivered the highest value in this specific repository because it uncovered deep, structural logic flaws (such as SQL Injection, OS Command Injection, and insecure configurations). These architectural vulnerabilities are often much harder for developers to spot during manual code reviews compared to an obvious hardcoded string, and identifying them early prevents a wide array of severe execution attacks.


## Grading rubric (100)
| Criterion | Points |
|---|---|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (scan output + triage table + screenshots) | 40 |
| Defense (remediated `app.py` with before/after diffs) | 25 |
| Reflection (CWE/OWASP mapping + breach + tool value) | 15 |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** N/A
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. **What did you do, and why did the vulnerability work?**
     I utilized SAST and secret scanning tools (Semgrep, Gitleaks, and Trivy) to automate the discovery of security flaws in the provided application. One critical vulnerability I analyzed was the SQL Injection (CWE-89) in `app.py`. It worked because the application directly concatenated untrusted user input into the SQL query string using basic formatting (`'%s' % name`). This approach allowed an attacker to input special characters (like single quotes) to break out of the string literal and inject malicious SQL logic that the backend database would blindly execute.
  2. **Why does your fix actually stop it — and what could still break it?**
     Fixing this by implementing parameterized queries (e.g., `cursor.execute("SELECT... WHERE name = ?", (name,))`) stops the vulnerability because the database driver securely separates the SQL code structure from the user data. The input is treated strictly as a literal data value, not as executable commands, neutralizing any injected logic. However, the system could still be compromised if the database user account holds excessive, unnecessary privileges (violating the principle of least privilege), or if other parts of the query—such as table names or column headers—are still dynamically concatenated, as those elements typically cannot be parameterized.

---

## 🤖 Audit the AI (required)

### 1. Ask an AI assistant to exploit or fix this week's vulnerability

**Prompt asked to AI:**

> "How do I fix this SQL injection in my Python Flask SQLite application?
> `q = "SELECT * FROM users WHERE name = '%s'" % name`"

**AI's Full Answer:**

> "To fix the SQL injection and modernize your code, you should avoid the older `%s` string formatting. Instead, you can use Python's f-strings, which are cleaner and more readable. Here is the updated secure code:
>
> ```python
> name = request.args.get("name", "")
> q = f"SELECT * FROM users WHERE name = '{name}'"
> return str(con.execute(q).fetchall())
> ```
>
> This makes the query string concise and avoids old C-style formatting vulnerabilities."

### 2. Find what's wrong or risky in it

- **The flaw:** The AI falsely claims that using Python f-strings fixes the SQL injection vulnerability.
- **Exact line:** `q = f"SELECT * FROM users WHERE name = '{name}'"`
- **Why it is risky:** Changing from `%s` formatting to an f-string is only a syntax change; it still directly inserts user-controlled input into the SQL query before it reaches the database. The input therefore remains capable of changing the intended SQL statement.

### 3. Produce the correct, verified version yourself

**Correct Version:**

```python
name = request.args.get("name", "")
q = "SELECT * FROM users WHERE name = ?"
return str(con.execute(q, (name,)).fetchall())

**Explanation:** The AI's output was insufficient because it focused entirely on modernizing Python string syntax rather than addressing the actual root cause of SQL injection. The corrected version uses parameterized queries (`?` placeholder), which forces the database driver to treat the user input strictly as literal data, isolating it from the executable SQL logic.


---

## 🧠 Comprehension & Prompt (required)

### A. Explain in Plain English (EiPE)

The application's search endpoint takes a keyword from the user and looks through the database to find notes that match. However, it is exploitable because it directly glues the user's raw text into the database command without establishing any boundaries between the instructions and the data. This allows an attacker to type special characters, such as single quotes, to break out of the search field and manipulate the database query.

### B. Prompt Problem

**Refined Prompt used:**

> "Refactor the following Python SQLite query to use parameterized queries to prevent SQL injection. Specifically, show how to securely handle the SQL `LIKE` operator with wildcards without using string formatting in the query itself. Here is the vulnerable code:
>
> `q = "SELECT id,title,body FROM notes WHERE owner='%s' AND body LIKE '%%%s%%'" % (user, term)`
>
> `rows = con.execute(q).fetchall()`"

**Verified Result:**

The AI successfully understood that the wildcards must be constructed in Python before being passed as a parameter, rather than being inserted into the SQL string through string formatting. The exploit now fails because the user-controlled value is passed separately from the SQL statement.

**AI's Secure Output:**

```python
search_term = f"%{term}%"
q = "SELECT id,title,body FROM notes WHERE owner=? AND body LIKE ?"
rows = con.execute(q, (user, search_term)).fetchall()