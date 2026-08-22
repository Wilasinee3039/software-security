# Sandbox/teaching only; for authorized lab use.
#
# Week 15 — the SECURE half of the "Break the Build" target. The same /admin
# endpoint as insecure_service.py, hardened for two OWASP-2025 items:
#   * A10 / CWE-636: FAIL CLOSED — any error path DENIES (403), never grants.
#   * A09: structured security logging of authn/authz events to a dedicated
#     "security" logger (ship to a SIEM, alert on failures) — never the secret.
#
# Same public behaviour on the happy path (a valid admin token still unlocks the
# panel) so the auto-verifier's functional check passes; the difference is that
# unauthenticated / malformed requests are DENIED and LOGGED instead of leaking.

import logging
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s level=%(levelname)s logger=%(name)s %(message)s",
)
security_log = logging.getLogger("security")

SECRET = os.environ.get("FLAG_DEVSECOPS", "FLAG{devsecops_fail_open_leaks_admin}")
USERS = {"alice-token": "alice", "bob-token": "bob"}
ADMINS = {"alice"}


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?")


@app.route("/")
def index():
    return jsonify(
        service="week15-devsecops SECURE demo",
        endpoints={"GET /admin": "Authorization: alice-token (fails CLOSED + logs)"},
    )


@app.route("/admin", methods=["GET"])
def admin():
    """Authorize. FAIL CLOSED: any error -> 403, never silently allow (A10)."""
    try:
        token = request.headers.get("Authorization", "")
        user = USERS.get(token)                  # .get() -> None, never raises

        if user is None:
            security_log.warning(
                "event=authz_failure outcome=deny src_ip=%s reason=unauthenticated",
                _client_ip(),
            )
            return jsonify(error="forbidden"), 403

        if user not in ADMINS:
            security_log.warning(
                "event=authz_failure outcome=deny subject=%s src_ip=%s reason=not_admin",
                user, _client_ip(),
            )
            return jsonify(error="forbidden"), 403

        security_log.info(
            "event=authz_success outcome=allow subject=%s src_ip=%s",
            user, _client_ip(),
        )
        return jsonify(panel="UNLOCKED", secret=SECRET)

    except Exception as exc:  # noqa: BLE001 — intentional broad catch
        # FAIL CLOSED (A10 / CWE-636): on ANY unexpected error, DENY and log.
        # Never leak the exception detail to the client (CWE-209).
        security_log.error(
            "event=authz_error outcome=deny src_ip=%s error=%s",
            _client_ip(), type(exc).__name__,
        )
        return jsonify(error="forbidden"), 403


if __name__ == "__main__":
    # Port 8091 (pairs with the insecure service on 8090).
    app.run(host="0.0.0.0", port=8091, debug=False)
