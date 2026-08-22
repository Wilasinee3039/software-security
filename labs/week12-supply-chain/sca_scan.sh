#!/usr/bin/env bash
# Sandbox/teaching only; for authorized lab use.
#
# Week 12 — Software Composition Analysis (SCA).
# Scans the pinned, intentionally-outdated dependencies two ways:
#   1) trivy fs    — filesystem scan of requirements.txt (no build needed)
#   2) pip-audit   — Python-specific advisory check (pip-audit "style")
# Plus an optional image scan once you have built the lab image.
#
# OWASP 2025 A03 Software Supply Chain Failures · CWE-1104 / CWE-1395.
# All work is done in throwaway Docker containers (--rm) so nothing is
# installed on the host. Idempotent: re-run as often as you like.

set -e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${1:-week12-supplychain:lab}"

echo "==> [1/3] trivy fs — scanning requirements.txt for vulnerable versions"
# Expected output: a table of CVEs against Flask/Werkzeug/Jinja2/requests/
# urllib3/PyYAML, each with an installed version and a fixed version.
docker run --rm -v "$HERE:/src" aquasec/trivy:latest \
  fs --scanners vuln --severity HIGH,CRITICAL /src || true

echo
echo "==> [2/3] pip-audit — Python advisory database check"
# Expected output: one line per vulnerable package with the advisory ID
# (GHSA-/PYSEC-) and the version that fixes it. Runs pip-audit inside a
# python image so the host stays clean.
docker run --rm -v "$HERE:/src" -w /src python:3.9-slim \
  sh -c "pip install --quiet pip-audit && pip-audit -r requirements.txt" || true

echo
echo "==> [3/3] trivy image (optional) — scans the built image's OS + libs"
# Only runs if you already built the image:
#   docker build -t $IMAGE .
# Expected output: OS-package CVEs (from the base image) PLUS the same
# Python CVEs found above. Demonstrates that image scanning is a superset.
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy:latest image --severity HIGH,CRITICAL "$IMAGE" || true
else
  echo "    (image '$IMAGE' not built yet — run: docker build -t $IMAGE . )"
fi

echo
echo "==> Done. Remediation = bump each flagged package to its fixed version."
