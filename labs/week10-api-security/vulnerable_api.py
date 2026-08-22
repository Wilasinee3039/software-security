"""Deliberately INSECURE — Week 10 API Security. Sandbox only; for authorized lab use.

Flaws (OWASP API Security Top 10:2023):
  API1:2023 BOLA              — GET /api/users/<id>/orders returns ANY user's orders.
  API3:2023 Mass Assignment  — POST /api/users binds the whole JSON body (incl. is_admin/balance).
  API4:2023 Unrestricted Resource Consumption — /api/login has no rate limiting (brute-force/DoS).

Run:  flask --app vulnerable_api run --port 5000   (or use docker-compose.yml)
"""
import os
from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG_BOLA = os.environ.get("FLAG_BOLA", "FLAG{bola_demo}")
FLAG_MASSASSIGN = os.environ.get("FLAG_MASSASSIGN", "FLAG{massassign_demo}")

# --- In-memory "database" -----------------------------------------------------
# Seed users. Note: balance + is_admin are SERVER-controlled fields a client
# must never be able to set directly.
USERS = {
    1: {"id": 1, "username": "alice", "password": "alice123",
        "balance": 100, "is_admin": False},
    2: {"id": 2, "username": "bob", "password": "bob123",
        "balance": 50, "is_admin": False},
    3: {"id": 3, "username": "carol", "password": "carol123",
        "balance": 9999, "is_admin": True},
}
ORDERS = {
    1: [{"order_id": "A-1", "item": "Keyboard", "total": 30}],
    2: [{"order_id": "B-1", "item": "Mouse", "total": 15}],
    3: [{"order_id": "C-1", "item": "Server rack", "total": 5000},
        {"order_id": "C-FLAG", "item": FLAG_BOLA, "total": 0}],
}
_next_id = 4


def current_user():
    """Toy "auth": trust the X-User-Id header. (In real apps use a verified token.)"""
    try:
        return USERS.get(int(request.headers.get("X-User-Id", 0)))
    except (TypeError, ValueError):
        return None


# --- API1:2023 BOLA -----------------------------------------------------------
# No check that the caller owns (or may view) user <uid>. Anyone can read anyone's
# orders just by changing the id in the URL.
@app.get("/api/users/<int:uid>/orders")
def get_orders(uid):
    return jsonify(ORDERS.get(uid, []))


# --- API3:2023 Mass Assignment ------------------------------------------------
# The whole JSON body is merged into the new record. A client can smuggle
# is_admin=true or balance=1000000 — fields they should never control.
@app.post("/api/users")
def create_user():
    global _next_id
    body = request.get_json(force=True) or {}
    user = {"id": _next_id}
    user.update(body)            # <-- mass assignment: trusts every key
    if user.get("is_admin"):     # smuggling is_admin=true grants the flag
        user["flag"] = FLAG_MASSASSIGN
    USERS[_next_id] = user
    _next_id += 1
    return jsonify(user), 201


# --- API4:2023 Unrestricted Resource Consumption ------------------------------
# No rate limiting / lockout -> unlimited password guessing (brute force) and DoS.
@app.post("/api/login")
def login():
    body = request.get_json(force=True) or {}
    for u in USERS.values():
        if u["username"] == body.get("username") and u["password"] == body.get("password"):
            return jsonify({"ok": True, "user_id": u["id"], "is_admin": u["is_admin"]})
    return jsonify({"ok": False}), 401


@app.get("/")
def index():
    return "Week 10 INSECURE API — see attack.md", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
