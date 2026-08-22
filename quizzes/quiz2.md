# Quiz 2 — Modern Stack (Weeks 10–15)

**Course:** Software Security (KOSEN69) · **Time:** 30 min · **Total:** 25 pts
**Covers:** API security · Memory safety & exploitation · Supply chain · Cloud/container · AI/LLM · DevSecOps

**Name:** ____________________  **Student ID:** ____________  **Date:** ________

---

## Part A — Multiple Choice (10 × 1 pt)

1. **BOLA** (API1) is essentially:
   a) XSS in an API b) IDOR at API scale c) a DoS d) a weak cipher

2. **Mass assignment** happens when:
   a) the server binds client-supplied fields it shouldn't b) too many requests arrive c) passwords are reused d) logs are missing

3. A **stack canary** defends against:
   a) SQL injection b) detecting a stack-buffer overwrite before return c) prompt injection d) weak TLS

4. The strongest long-term fix for memory-safety bugs is:
   a) more code review b) ASLR c) memory-safe languages (Rust/Go) d) bigger buffers

5. **Dependency confusion** abuses:
   a) a public package shadowing an internal name b) a stack overflow c) an open S3 bucket d) a weak JWT

6. An **SBOM** is:
   a) a signature b) an inventory of software components c) a firewall rule d) a fuzzing harness

7. **Cosign** is used to:
   a) scan code b) sign & verify artifacts/images c) generate passwords d) write IAM policies

8. The most common root cause of cloud breaches is:
   a) zero-days b) misconfiguration (A02) c) DDoS d) weak crypto

9. **Indirect prompt injection** delivers the malicious instruction via:
   a) the system prompt b) content the model ingests (e.g. a fetched document/RAG) c) the model weights d) the GPU

10. A security CI gate should, on a HIGH/CRITICAL finding:
    a) log and continue b) email later c) **fail the build** d) ignore it

---

## Part B — Short Answer (3 × 3 pts)

11. Name the two **object/field-level** API risks from this week and give a one-line fix for each.

12. Explain **least privilege** for an IAM policy and rewrite the intent of `{"Action":"*","Resource":"*"}` in words to make it least-privilege for read-only S3 access.

13. Why must LLM **output be treated as untrusted**? Give one concrete downstream harm and one mitigation.

---

## Part C — Applied (2 × 3 pts)

14. You inherit a `Dockerfile` that uses `FROM ubuntu:latest`, runs as root, and bakes `AWS_SECRET` in an `ENV`. List the three problems and the fix for each.

15. Describe the **"Break the Build"** pipeline: name the three scanners and what each catches, and the condition that should fail the build.
