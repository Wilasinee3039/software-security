
from audit_fixed_api import app

with app.test_client() as client:

    # Test 1: Spoof Carol without login
    r = client.get(
        "/api/users/3/orders",
        headers={"X-User-Id": "3"}
    )
    print("Test 1 - Spoofed header:", r.status_code, r.get_json())

    # Test 2: Login as Alice
    r = client.post(
        "/api/login",
        json={
            "username": "alice",
            "password": "alice123"
        }
    )
    print("Test 2 - Alice login:", r.status_code, r.get_json())

    # Test 3: Alice tries to access Carol's orders
    r = client.get(
        "/api/users/3/orders",
        headers={"X-User-Id": "3"}
    )
    print("Test 3 - Alice to Carol:", r.status_code, r.get_json())

    # Test 4: Alice accesses her own orders
    r = client.get("/api/users/1/orders")
    print("Test 4 - Alice to Alice:", r.status_code, r.get_json())
