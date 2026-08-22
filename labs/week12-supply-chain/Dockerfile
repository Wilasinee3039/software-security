# Sandbox/teaching only; for authorized lab use.
#
# Week 12 — tiny image so we can practice `trivy image` and SBOM generation.
# This Dockerfile is deliberately modest (not a hardening exercise — that is
# week 13). It will still produce CVE findings because requirements.txt is
# intentionally outdated (OWASP A03 Software Supply Chain Failures).

# Pinned tag (not :latest) so the lab is reproducible. CWE-1104 avoidance.
FROM python:3.9-slim

WORKDIR /app

# Copy only the dependency manifest first so Docker layer caching works.
COPY requirements.txt .

# Install the (intentionally vulnerable) dependencies.
# --no-cache-dir keeps the image small and avoids stale pip caches.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code.
COPY app.py .

EXPOSE 5000

# Run the app. In a real image you would also add a non-root USER here —
# see week13/Dockerfile.hardened for that.
CMD ["python", "app.py"]
