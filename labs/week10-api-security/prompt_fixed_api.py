
"""Week 10 - Prompt Problem: Secure Flask API.
Uses signed Flask sessions instead of X-User-Id.
Local educational lab only.
"""

import os
import secrets
import time
from collections import defaultdict

from flask import Flask, jsonify, request, session
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY")
    or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

# In-memory database
USERS = {
    1: {
        "id": 1,
        "username": "alice",
        "password_hash": generate_password_hash("alice123"),
        "balance": 100,
        "is_admin": False,
    },
    2: {
        "id": 2,
        "username": "bob",
        "password_hash": generate_password_hash("bob123"),
        "balance": 50,
        "is_admin": False,
    },
    3: {
        "id": 3,
        "username": "carol",
        "password_hash": generate_password_hash("carol123"),
        "balance": 9999,
        "is_admin": True,
    },
}

ORDERS = {
    1: [{"order_id": "A-1", "item": "Keyboard", "total": 30}],
    2: [{"order_id": "B-1", "item": "Mouse", "total": 15}],
    3: [{"order_id": "C-1", "item": "Server rack", "total": 5000}],
}

_next_id = 4

ALLOWED_CREATE_FIELDS = {"username", "password"}


# FIX API1: Verified session instead of X-User-Id
def current_user():
    user_id = session.get("user_id")

    if type(user_id) is not int:
        return None

    return USERS.get(user_id)


@app.get("/api/users/<int:uid>/orders")
def get_orders(uid):
    caller = current_user()

    if caller is None:
        return jsonify({
            "error": "authentication required"
        }), 401

    if caller["id"] != uid and not caller["is_admin"]:
        return jsonify({
            "error": "forbidden"
        }), 403

    return jsonify(ORDERS.get(uid, [])), 200


# FIX API3: Allow-list binding
@app.post("/api/users")
def create_user():
    global _next_id

    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        return jsonify({
            "error": "JSON object required"
        }), 400

    user = {
        k: body[k]
        for k in ALLOWED_CREATE_FIELDS
        if k in body
    }

    username = user.get("username")
    password = user.get("password")

    if (
        not isinstance(username, str)
        or not username.strip()
        or not isinstance(password, str)
        or not password
    ):
        return jsonify({
            "error": "username and password required"
        }), 400

    record = {
        "id": _next_id,
        "username": username,
        "password_hash": generate_password_hash(password),
        "balance": 0,
        "is_admin": False,
    }

    USERS[_next_id] = record
    _next_id += 1

    return jsonify({
        "id": record["id"],
        "username": record["username"],
        "balance": record["balance"],
        "is_admin": record["is_admin"],
    }), 201


# FIX API4: Rate limiting
RATE_LIMIT = 5
RATE_WINDOW = 60

_attempts = defaultdict(list)


def rate_limited(ip):
    now = time.time()

    _attempts[ip] = [
        t for t in _attempts[ip]
        if now - t < RATE_WINDOW
    ]

    if len(_attempts[ip]) >= RATE_LIMIT:
        return True

    _attempts[ip].append(now)
    return False


@app.post("/api/login")
def login():
    ip = request.remote_addr or "unknown"

    if rate_limited(ip):
        return jsonify({
            "error": "too many requests"
        }), 429

    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        return jsonify({
            "error": "JSON object required"
        }), 400

    username = body.get("username")
    password = body.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"ok": False}), 401

    for user in USERS.values():
        if (
            user["username"] == username
            and check_password_hash(
                user["password_hash"], password
            )
        ):
            session.clear()
            session["user_id"] = user["id"]

            return jsonify({
                "ok": True,
                "user_id": user["id"],
                "is_admin": user["is_admin"],
            }), 200

    return jsonify({"ok": False}), 401


@app.get("/")
def index():
    return "Week 10 PROMPT-FIXED API", 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002)
