# Week 10 — API Security: Attack Walkthrough

Start the labs:

```bash
docker compose up        # INSECURE on :8080, SECURE on :8081
```

Seeded users: `alice` (id 1), `bob` (id 2), `carol` (id 3, admin, balance 9999).

---

## API1:2023 — Broken Object Level Authorization (BOLA)

The insecure API never checks who is asking. Read carol's (admin) orders as nobody:

```bash
# INSECURE — leaks any user's orders by changing the id
curl http://localhost:8080/api/users/3/orders
curl http://localhost:8080/api/users/2/orders
```

On the **secure** API the same request is rejected unless you own the object:

```bash
# 401 — no identity
curl -i http://localhost:8081/api/users/3/orders

# 403 — alice (id 1) may not read carol's (id 3) orders
curl -i -H "X-User-Id: 1" http://localhost:8081/api/users/3/orders

# 200 — alice reading her own orders is allowed
curl -i -H "X-User-Id: 1" http://localhost:8081/api/users/1/orders
```

---

## API3:2023 — Mass Assignment (Broken Object Property Level Auth)

Smuggle privileged fields the client should never control:

```bash
# INSECURE — we set is_admin + balance ourselves
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"mallory","password":"x","is_admin":true,"balance":1000000}'
# -> response shows "is_admin": true, "balance": 1000000
```

On the **secure** API only allow-listed fields bind; server forces the rest:

```bash
curl -X POST http://localhost:8081/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"mallory","password":"x","is_admin":true,"balance":1000000}'
# -> "is_admin": false, "balance": 0   (smuggled fields ignored)
```

---

## API4:2023 — Unrestricted Resource Consumption (no rate limit)

Brute-force the login endpoint — the insecure API never throttles:

```bash
# INSECURE — runs as many guesses as you like
for pw in wrong1 wrong2 wrong3 alice123; do
  curl -s -X POST http://localhost:8080/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"alice\",\"password\":\"$pw\"}"; echo
done
```

On the **secure** API the 6th attempt within 60s returns `429 Too Many Requests`:

```bash
for i in $(seq 1 7); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8081/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"wrong"}'
done
# -> 401 401 401 401 401 429 429
```

---

## Deliverable

Map each finding to the OWASP API Top 10 id, show the exploit curl, then show the
fix in `solution_api.py` that defeats it.
