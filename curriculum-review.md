# Curriculum Review — Is This Course Modern? (Benchmarked vs. Top Universities)

*Reviewed June 2026. Compares the KOSEN69 19-week plan against leading software/computer-security courses and the 2025–2026 threat landscape.*

---

## TL;DR

**The course is more modern than most elite university courses**, not less. Its dedicated units on **software supply chain (SLSA/SBOM/Cosign)**, **cloud/container security**, **AI/LLM security**, and **DevSecOps CI/CD** are exactly the areas traditional courses are only *now* starting to bolt on — usually as a single guest lecture. The game/CTF-per-week pedagogy is also current best practice.

**Three gaps worth closing** to match the rigor of top programs: (1) **fuzzing & dynamic program analysis**, (2) a stronger **memory-safe-languages / "secure by design" policy** thread, and (3) **agentic-AI / MCP security** in the LLM week. None require restructuring — they slot into existing weeks.

---

## What the leading courses actually teach (2025–2026)

| Course | Core topics | Notable modern additions | Pedagogy |
|---|---|---|---|
| **MIT 6.858 / 6.5660** (Computer Systems Security) | Threat models, control hijacking, buffer overflows + defenses, privilege separation, capabilities, sandboxing, web security, symbolic execution, network/SSL, **side-channel attacks**, auth, anonymity | Research-paper driven; side-channels | Build-and-break labs (secure web server) + group project |
| **Stanford CS155** (Spring 2026) | Control hijacking, **vulnerability testing/fuzzing**, isolation/sandboxing, **hardware/microarchitecture security**, web (XSS/SQLi/CSRF), crypto, HTTPS pitfalls, network, privacy/anonymity | **"Security of AI Systems" + "Defeating Prompt Injection by Design"**; **Supply-Chain Risk** (guest: Socket founder) | Lectures + projects; industry guest lectures |
| **CMU 18-732** (Secure Software Systems) | Runtime policy enforcement (taint analysis), architectural confinement/VMs/trusted computing, **static analysis & model checking**, **language-based security (type systems, proof-carrying code)** | Formal / PL-heavy rigor | Exams + homework |
| **UC Berkeley CS161** (2025) | Crypto, memory safety, web security, network security | Intro-level breadth | Projects |
| **UMD Software Security** (Hicks, Coursera) | Memory attacks, web security, **secure design & threat modeling**, **static analysis + symbolic execution**, **fuzzing & pen-testing** | Strong program-analysis thread | MOOC + tools |

**Industry / 2026 signal:** new pro tracks (CAISP, MITRE ATLAS) center on **AI threat modeling, AI supply chain, adversarial attacks**, and — as of **Oct 2025** — **agentic-AI / GenAI and MCP-ecosystem attacks** (tool poisoning, RCE, supply-chain tampering inside agent tooling).

---

## Where this course is AHEAD of the field ✅

1. **Software supply-chain security as a full unit** (Wk12: dependency confusion, SBOM, SLSA, Cosign). Most universities have *nothing* here; Stanford 2026 only just added it as one guest lecture. This is genuinely current (OWASP 2025 made it a new top-tier category).
2. **Cloud & container security** (Wk13: IAM, secrets, Dockerfile/Trivy hardening). Almost absent from MIT/Berkeley/UMD. Directly job-relevant.
3. **AI/LLM application security** (Wk14: OWASP LLM Top 10, prompt injection, guardrails). Only Stanford 2026 matches this; you go deeper with a hands-on lab.
4. **DevSecOps / security CI-CD pipeline** (Wk15: SAST+SCA+secret-scanning gating a build). Rare as a taught, hands-on topic — most courses stop at "here are the tools."
5. **OWASP 2025 alignment + CTF/game-based learning every week.** Matches the modern, engagement-first pedagogy that top programs are moving toward (build-and-break, leaderboards).

> **Bottom line:** the "modern stack" half (Wk10–16) is the course's standout differentiator and is more current than the canonical syllabi above.

---

## Gaps to close (to match top-tier rigor) ⚠️

### 1. Fuzzing & dynamic program analysis — *the biggest gap*
Stanford, UMD, and CMU all teach **fuzzing, static analysis, and symbolic execution** as first-class bug-finding techniques. The course currently has SAST (Semgrep, Wk2) but **no fuzzing or dynamic analysis**. Fuzzing is arguably the single most impactful modern vulnerability-discovery method (it's how most real CVEs are found today).
- **Fix (low cost):** add a fuzzing segment to **Wk2** (coverage-guided fuzzing intro) or **Wk11** (fuzz the C binary with AFL++/libFuzzer before exploiting it). Great game potential: *"Fuzzing Race — first team to crash the target wins."*

### 2. Memory-safe languages & "Secure by Design" policy thread
The global shift to memory-safe languages is a defining 2024–2026 story (**CISA/ONCD memory-safety roadmaps**, **CISA "Secure by Design"** pledge). The course mentions "why Rust/Go matter" in Wk11 but doesn't foreground it.
- **Fix:** amplify in **Wk11** — frame memory bugs as *why the industry/government is mandating memory-safe languages*, with a short Rust "rewrite the vulnerable routine safely" sub-lab. Very current, very motivating.

### 3. Agentic-AI / MCP security in the LLM week
Wk14 covers the OWASP LLM Top 10, but the newest threat surface (post-Oct 2025) is **autonomous agents and the MCP tool ecosystem** — tool poisoning, excessive agency, RCE via agent tools.
- **Fix:** add a short module/demo to **Wk14** on agent/MCP risks + least-privilege tool design. Keeps you at the very front of the field.

### Optional (scope calls — defensible to omit for a *software*-security course)
- **Network security depth** (TLS internals, DNSSEC, DoS, firewalls): big at Stanford/Berkeley/MIT. You cover TLS "high level" only — fine if this stays a *software* (not *network*) security course, but worth stating explicitly.
- **Hardware / microarchitectural side-channels** (Spectre/Meltdown): MIT + Stanford cover. Likely too advanced for this level — a single awareness slide is enough.
- **Formal / language-based security** (type systems, proof-carrying code): CMU's specialty. Out of scope here; OK to skip.

---

## Recommended edits (minimal, high-impact)

| Week | Add | Effort |
|---|---|---|
| **Wk2** | Coverage-guided **fuzzing** intro + "Fuzzing Race" mini-game | Low |
| **Wk11** | **AFL++/libFuzzer** to find the bug before exploiting; **Rust safe-rewrite** + memory-safe-language policy framing | Low–Med |
| **Wk14** | **Agentic-AI / MCP security** demo (tool poisoning, least-privilege tools) | Low |
| **Wk1/Wk15** | One slide each: "Secure by Design" (CISA) + the memory-safety national push | Trivial |

These three additions move the course from "more modern than most" to **"genuinely state-of-the-art (2026)"** while keeping the 19-week structure and the game-per-week theme intact.

---

## Sources

- [MIT 6.858 Computer Systems Security — Syllabus (OCW)](https://ocw.mit.edu/courses/6-858-computer-systems-security-fall-2014/pages/syllabus/) · [Spring 2023 (6.5660)](https://css.csail.mit.edu/6.858/2023/)
- [Stanford CS155 — Course site](https://cs155.stanford.edu/) · [Syllabus (Spring 2026)](https://cs155.stanford.edu/syllabus.html)
- [CMU Secure Software Systems (18-335/18-732)](https://www.cylab.cmu.edu/education/course-list/secure-software.html) · [18-732 syllabus](https://course.ece.cmu.edu/~ece732/s18/syllabus.html)
- [UC Berkeley CS161 — Fall 2025](https://fa25.cs161.org/) · [Textbook](https://textbook.cs161.org/)
- [UMD Software Security (Michael Hicks) — Class Central](https://www.classcentral.com/course/software-security-1728) · [Course page](https://mhicks.me/courses/software-security/)
- [A Generative Security Application Engineering Curriculum (arXiv 2501.10900)](https://arxiv.org/pdf/2501.10900)
- [LLM Security courses overview — Class Central](https://www.classcentral.com/subject/llm-security)
- [MITRE ATLAS — securing AI / agentic threats (Practical DevSecOps)](https://www.practical-devsecops.com/mitre-atlas-framework-guide-securing-ai-systems/)
