# Weekly Quiz — Week 14 (AI / LLM Security)

**~10 min · in-class · 6 questions · low-stakes** (drop lowest). No devices / locked browser.

**Name:** ____________  **Student ID:** ________

## MCQ (5 × 1)
1. **Prompt injection** (the #1 LLM risk) is when:
   a) the prompt is too long  b) untrusted input overrides the app's instructions  c) the model is slow  d) the API key leaks
2. Why must you **not** trust LLM output in a security-sensitive code path?
   a) it is copyrighted  b) it can hallucinate or be manipulated  c) it is always wrong  d) it is too short
3. A core mitigation for prompt injection is to:
   a) make the prompt longer  b) treat model output as untrusted + least-privilege tools + separate data from instructions  c) raise temperature  d) disable logging
4. **Training-data poisoning** targets:
   a) the network  b) the model's learned behavior  c) the GPU  d) the cache
5. **Sensitive information disclosure** in LLM apps is when the model:
   a) is rate-limited  b) leaks secrets/PII present in its context  c) refuses a task  d) returns JSON

## Short answer — 🔒 your own work (1 × 3)
6. Paste the **prompt-injection input** that captured the flag in this week's lab and explain why the **guardrail failed**. Then paste your **personal flag** (`FLAG{...}`) captured from the challenge.
