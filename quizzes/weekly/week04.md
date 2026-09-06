# Weekly Quiz — Week 4 (Injection)

**~10 min · in-class · 6 questions · low-stakes** (drop lowest). No devices / locked browser.

**Name:** Wilasinee Mangkorn  **Student ID:** 6631503039

## MCQ (5 × 1)
1. The input `' OR '1'='1` against a login form targets:
  **b) SQL injection (auth bypass)**
**Explanation:**
This payload changes the SQL condition to always be true, allowing attackers to bypass the login check without a valid password.
2. The strongest defense against SQL injection is:
   **c) parameterized queries / prepared statements**
**Explanation:**
Parameterized queries separate SQL code from user input, so the input is treated as data instead of executable SQL commands.
3. OS command injection happens when:
   **b) user input is passed into a shell command**
**Explanation:**
If user input is included in a shell command, attackers may inject additional commands that the operating system executes.
4. The CWE id for SQL injection is:
   **c) CWE-89**
**Explanation:**
CWE-89 specifically refers to SQL Injection vulnerabilities.
5. Which does **not** by itself stop SQLi in the query?
   **d) HTML output encoding**
**Explanation:**
HTML encoding helps prevent XSS attacks, but it does not protect SQL queries from injection.

## Short answer — 🔒 your own work (1 × 3)
6. From this week's **SQLi Boss Fight**, paste the **exact payload** you used to log in as admin and explain in one sentence **why** it worked. Then paste your **personal flag** (`FLAG{...}`) captured from the challenge.

**Payload:** `admin'--`

**Explanation:**  
The payload worked because the application directly concatenated user input into the SQL query, and the -- symbol commented out the password condition, allowing login without knowing the correct password.

**Personal flag:** `FLAG{sqli_demo}`
