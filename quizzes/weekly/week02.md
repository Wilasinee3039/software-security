# Weekly Quiz — Week 2 (Secure SDLC, Tooling & Fuzzing)

**~10 min · 6 questions · low-stakes** (lowest scores dropped). Individual.

**Name:** Wilasinee Mangkorn  **Student ID:** 6631503039

## MCQ (5 × 1)
1. **SAST** analyzes:
   **b) source code without running it**
2. The tool type that finds **hardcoded secrets** in code/history is:
   **c) secret scanning**
3. Coverage-guided **fuzzing** finds bugs by:
   **b) mutating inputs and watching for new paths/crashes**
4. A **false positive** is:
   **b) a flagged finding that is not actually a bug**
5. **SCA** checks:
   **b) dependencies for known CVEs**

## Short answer (1 × 3)
6. Name **one** bug SAST would catch that DAST would not — and one DAST would catch that SAST would not.
   * **SAST catches but DAST misses:** A hardcoded encryption key or secret hidden deep within the backend source code that is never exposed to the web interface. 
   * **DAST catches but SAST misses:** A runtime server misconfiguration, such as missing HTTP security headers or an exposed server port, which only exists when the application is actively running and deployed.