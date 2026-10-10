
"""Verification for the Prompt Problem API."""

from prompt_fixed_api import app


def check(label, response, expected_status):
    actual = response.status_code
    print(f"{label}: {actual} {response.get_json()}")

    assert actual == expected_status, (
        f"Expected {expected_status}, got {actual}"
    )


with app.test_client() as client:

    # Test 1: Spoof Carol without login
    check(
        "Test 1 - Spoofed header",
        client.get(
            "/api/users/3/orders",
            headers={"X-User-Id": "3"}
        ),
        401
    )

    # Test 2: Login as Alice
    check(
        "Test 2 - Alice login",
        client.post(
            "/api/login",
            json={
                "username": "alice",
                "password": "alice123"
            }
        ),
        200
    )

    # Test 3: Alice tries to access Carol's orders
    check(
        "Test 3 - Alice to Carol",
        client.get(
            "/api/users/3/orders",
            headers={"X-User-Id": "3"}
        ),
        403
    )

    # Test 4: Alice accesses her own orders
    check(
        "Test 4 - Alice to Alice",
        client.get("/api/users/1/orders"),
        200
    )

    # Test 5: Mass assignment
    created = client.post(
        "/api/users",
        json={
            "username": "mallory",
            "password": "x",
            "is_admin": True,
            "balance": 1000000
        }
    )

    check("Test 5 - Mass assignment", created, 201)

    assert created.get_json()["is_admin"] is False
    assert created.get_json()["balance"] == 0
    assert "password" not in created.get_json()
    assert "password_hash" not in created.get_json()

    # Test 6: Rate limiting
    statuses = []

    for i in range(7):
        response = client.post(
            "/api/login",
            json={
                "username": "alice",
                "password": "wrong"
            },
            environ_overrides={
                "REMOTE_ADDR": "203.0.113.7"
            }
        )
        statuses.append(response.status_code)

    print("Test 6 - Rate limiting:", statuses)

    assert statuses == [
        401, 401, 401, 401, 401, 429, 429
    ]


print("All six verification checks passed.")
