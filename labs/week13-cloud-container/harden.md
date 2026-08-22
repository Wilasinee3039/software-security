<!-- Sandbox/teaching only; for authorized lab use. -->

# Hardening Checklist — Misconfig → Fix

**OWASP 2025:** A02 Security Misconfiguration · **CWE:** CWE-732, CWE-16, CWE-250, CWE-798

Run `./scan.sh` against the *insecure* artifacts, fix each row, then re-run to
watch the findings disappear.

## Container image (`Dockerfile.insecure` → `Dockerfile.hardened`)

| # | Misconfiguration (insecure) | CWE | Fix (hardened) |
|---|------------------------------|-----|----------------|
| 1 | `FROM python:latest` (unpinned, mutable) | CWE-1104 / CWE-16 | Pin to a **digest** (`@sha256:...`); use a slim/distroless base |
| 2 | Secret in `ENV API_TOKEN=...` | CWE-798 / CWE-200 | **No secrets in image.** Inject at runtime via secrets manager / mounted secret |
| 3 | `COPY . .` (whole context) | CWE-538 | Copy only needed files; add a `.dockerignore` (exclude `.git`, `.env`, keys) |
| 4 | `chmod -R 777 /app` | CWE-732 | Default perms; app owned by non-root, not world-writable |
| 5 | Runs as root (no `USER`) | CWE-250 | `USER 65532:65532` (non-root); distroless `nonroot` |
| 6 | Unpinned `pip install` | CWE-1104 | Pinned `requirements.txt` (+ hashes) in a build stage |

### Extra runtime hardening (not in the Dockerfile, enforce at deploy)
- `docker run --read-only --cap-drop ALL --security-opt no-new-privileges`
- Set resource limits (`--memory`, `--pids-limit`) to blunt DoS.
- Never `--privileged`; never mount the Docker socket into untrusted containers.

## IAM (`iam-policy-insecure.json` → `iam-policy-leastpriv.json`)

| # | Misconfiguration | CWE | Fix |
|---|------------------|-----|-----|
| 7 | `"Action": "*"` | CWE-269 | Enumerate only the actions used (e.g. `s3:GetObject`) |
| 8 | `"Resource": "*"` | CWE-732 | Scope to specific ARNs (one bucket + prefix) |
| 9 | No conditions | CWE-732 | Add `Condition` (e.g. `s3:prefix`, source IP, MFA) |

### Principle
**Least privilege + shared responsibility:** grant the minimum, on the
minimum, under the right conditions. The cloud provider secures *of* the
cloud; you secure what you put *in* it.

## Deliverable
Before/after `scan.sh` output (finding counts) + the diffed policy and
Dockerfile, with one sentence per fix on why it reduces risk.
