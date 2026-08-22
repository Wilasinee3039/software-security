# Sandbox/teaching only; for authorized lab use.
#
# Week 15 — the INSECURE half of the "Break the Build" target. Two OWASP-2025
# bugs, on purpose, so the Blue team's pipeline + hardening has something to catch:
#   * A10 Mishandling of Exceptional Conditions (CWE-636): /admin FAILS OPEN —
#     on ANY error it swallows the exception and grants access.
#   * A09 Security Logging & Alerting Failures: auth failures are SILENT — no
#     security logger, so nothing can be alerted on.
#
# The fixed counterpart is secure_service.py. The auto-verifier suite is
# instructor/platform-build/defend/exploits_week15.py.

import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# The admin "secret" is the per-student flag when spawned on the platform
# (docker-compose injects FLAG_DEVSECOPS from seed_flags.py); the default only
# applies to a bare local run.
SECRET = os.environ.get("FLAG_DEVSECOPS", "FLAG{devsecops_fail_open_leaks_admin}")

# Toy token store. In real life: hashed creds + a real IdP.
USERS = {"alice-token": "alice", "bob-token": "bob"}
ADMINS = {"alice"}


@app.route("/")
def index():
    return jsonify(
        service="week15-devsecops INSECURE demo",
        endpoints={"GET /admin": "Authorization: alice-token (but it fails OPEN...)"},
    )


@app.route("/admin", methods=["GET"])
def admin():
    # BUG: the lookup uses dict indexing, so a missing/unknown token raises
    # KeyError — and the except block below FAILS OPEN instead of denying.
    try:
        token = request.headers.get("Authorization", "")
        user = USERS[token]                      # KeyError on unknown/empty token
        if user not in ADMINS:
            return jsonify(error="forbidden"), 403
        return jsonify(panel="UNLOCKED", secret=SECRET)
    except Exception:
        # A10 / CWE-636 FAIL OPEN: swallow the error and grant access anyway.
        # A09: no security logging here either — the bypass is completely silent.
        return jsonify(panel="UNLOCKED", secret=SECRET)


if __name__ == "__main__":
    # debug is off, but the auth logic is the point — an unauthenticated GET
    # /admin returns the admin panel because the error path fails open.
    # Port 8090 (not 7000: macOS ControlCenter/AirPlay squats 7000).
    app.run(host="0.0.0.0", port=8090, debug=False)
