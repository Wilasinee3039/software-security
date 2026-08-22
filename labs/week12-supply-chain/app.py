# Sandbox/teaching only; for authorized lab use.
#
# Week 12 — minimal Flask app whose only purpose is to be built into an
# image and scanned (trivy fs / trivy image). It deliberately pulls in the
# OUTDATED packages from requirements.txt so the dependency tree is scannable.
#
# Security note: this app is intentionally simple, not hardened. Do not deploy.

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def index():
    # Tiny endpoint so the container has something to serve.
    return jsonify(status="ok", note="supply-chain SCA lab target")


@app.route("/health")
def health():
    return jsonify(healthy=True)


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from outside the container in the lab.
    # debug=False on purpose: Flask's debugger (Werkzeug) is an RCE vector
    # when exposed (CWE-489 active debug code).
    app.run(host="0.0.0.0", port=5000, debug=False)
