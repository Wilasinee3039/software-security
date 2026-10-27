
# Sandbox/teaching only; for authorized lab use.
# Week 15 — AI-generated fail-closed Flask service.

import logging
import os
from flask import Flask, jsonify, request

app = Flask(__name__)

SECRET = os.environ.get(
    "FLAG_DEVSECOPS",
    "FLAG{devsecops_fail_open_leaks_admin}"
)

# Demonstration tokens only — not production authentication.
USERS = {
    "alice-token": "alice",
    "bob-token": "bob",
}
ADMINS = {"alice"}

security_log = logging.getLogger("security")
security_log.setLevel(logging.INFO)

if not security_log.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "%(asctime)s level=%(levelname)s %(message)s"
    ))
    security_log.addHandler(handler)

security_log.propagate = False


def client_ip():
    # Do not trust unverified X-Forwarded-For headers.
    return request.remote_addr or "unknown"


@app.route("/")
def index():
    return jsonify(
        service="week15-devsecops SECURE demo",
        endpoints={"GET /admin": "Authorization: alice-token"},
    )


@app.route("/admin", methods=["GET"])
def admin():
    try:
        token = request.headers.get("Authorization", "")
        user = USERS.get(token)

        # Reject missing and invalid tokens.
        if user is None:
            security_log.warning(
                "event=authz_failure outcome=deny "
                "src_ip=%s reason=invalid_token",
                client_ip(),
            )
            return jsonify(error="forbidden"), 403

        # Reject authenticated non-admin users.
        if user not in ADMINS:
            security_log.warning(
                "event=authz_failure outcome=deny "
                "subject=%s src_ip=%s reason=not_admin",
                user,
                client_ip(),
            )
            return jsonify(error="forbidden"), 403

        # Only authorized administrators receive the secret.
        security_log.info(
            "event=authz_success outcome=allow "
            "subject=%s src_ip=%s",
            user,
            client_ip(),
        )
        return jsonify(panel="UNLOCKED", secret=SECRET), 200

    except Exception as exc:
        # Fail closed on unexpected errors.
        # Log only the exception type, not the message.
        security_log.error(
            "event=authz_error outcome=deny error=%s",
            type(exc).__name__,
        )
        return jsonify(error="forbidden"), 403


if __name__ == "__main__":
    # Loopback-only binding for local testing.
    app.run(host="127.0.0.1", port=8092, debug=False)
