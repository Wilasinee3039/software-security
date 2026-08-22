# Sandbox/teaching only; for authorized lab use.
#
# Week 15 — tiny Flask service demonstrating two A09/A10 practices:
#   * Structured security logging of authn/authz events (OWASP A09
#     Security Logging & Alerting Failures).
#   * FAIL-CLOSED error handling: on any unexpected exception we DENY
#     (OWASP A10 Mishandling of Exceptional Conditions; CWE-636
#     "not failing securely / fail open").
#
# A commented-out INSECURE "fail-open" variant is included for contrast.

import logging
from flask import Flask, request, jsonify

app = Flask(__name__)

# ------------------------------------------------------------------
# Structured security logging.
# A dedicated "security" logger keeps auth events separate from app noise,
# so they can be shipped to a SIEM and alerted on. We log WHAT happened,
# WHO (subject), and the OUTCOME — never the secret/password itself
# (CWE-532: do not log sensitive data).
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s level=%(levelname)s logger=%(name)s %(message)s',
)
security_log = logging.getLogger("security")

# Toy "database". In real life: hashed passwords + a real store.
_VALID_TOKENS = {"alice-token": "alice", "bob-token": "bob"}
_ADMINS = {"alice"}


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?")


@app.route("/")
def index():
    return jsonify(
        service="week15-devsecops demo",
        endpoints={"POST /login": "JSON {token}", "GET /admin": "needs alice-token"},
    )


@app.route("/login", methods=["POST"])
def login():
    """Authenticate. Log both success and failure (A09)."""
    token = (request.json or {}).get("token", "")
    user = _VALID_TOKENS.get(token)

    if user is None:
        # AUTHN FAILURE — log it (no token value!) so it can be alerted on.
        security_log.warning(
            "event=authn_failure outcome=deny src_ip=%s reason=bad_token",
            _client_ip(),
        )
        return jsonify(error="authentication failed"), 401

    security_log.info(
        "event=authn_success outcome=allow subject=%s src_ip=%s",
        user, _client_ip(),
    )
    return jsonify(status="ok", user=user)


@app.route("/admin", methods=["GET"])
def admin():
    """Authorize. Fail CLOSED: any error -> 403, never silently allow."""
    try:
        token = request.headers.get("Authorization", "")
        user = _VALID_TOKENS.get(token)

        if user is None:
            security_log.warning(
                "event=authz_failure outcome=deny src_ip=%s reason=unauthenticated",
                _client_ip(),
            )
            return jsonify(error="forbidden"), 403

        if user not in _ADMINS:
            # AUTHZ FAILURE — authenticated but not allowed (privilege check).
            security_log.warning(
                "event=authz_failure outcome=deny subject=%s src_ip=%s "
                "reason=not_admin", user, _client_ip(),
            )
            return jsonify(error="forbidden"), 403

        security_log.info(
            "event=authz_success outcome=allow subject=%s src_ip=%s",
            user, _client_ip(),
        )
        return jsonify(secret="the cake is a lie")

    except Exception as exc:  # noqa: BLE001 — intentional broad catch
        # FAIL CLOSED (A10 / CWE-636): on ANY unexpected error, DENY and log.
        # We never leak the exception detail to the client (CWE-209).
        security_log.error(
            "event=authz_error outcome=deny src_ip=%s error=%s",
            _client_ip(), type(exc).__name__,
        )
        return jsonify(error="forbidden"), 403

    # ------------------------------------------------------------------
    # INSECURE "fail-open" variant — DO NOT USE. Shown for contrast.
    # Catching the error and allowing access turns a bug into a bypass:
    #
    # except Exception:
    #     return jsonify(secret="the cake is a lie")   # <-- A10 / CWE-636!
    # ------------------------------------------------------------------


if __name__ == "__main__":
    # debug=False: Werkzeug debugger is an RCE vector if exposed (CWE-489).
    app.run(host="127.0.0.1", port=5001, debug=False)
