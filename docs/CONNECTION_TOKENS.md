# Per-user connection tokens

By default the server trusts the `uid` header a client sends. That is safe **only
when the client API key never reaches end users** — i.e. a trusted backend holds
the key and connects on the user's behalf. If clients connect to the server
directly (a browser or mobile app opens the WebSocket), the client key is not a
secret, and anyone can present any `uid`: impersonate a user, read their cache
rooms, or block their reconnects.

Connection tokens close that gap. When enabled, every `uid`-bearing request must
carry a `token` header proving the caller owns that `uid`. The token is minted by
your backend (which alone holds the secret) at login.

## Enabling

Set the secret at startup:

```
docker run ... -e SL_CONNECTION_TOKEN_SECRET='a-long-random-secret' sl-server
```

or at runtime:

```
POST /api/v1/invalidate   {"connection_token_secret": "a-long-random-secret"}
```

Once a secret is set, these surfaces reject any request whose token does not
verify (HTTP 401 / WS upgrade 401):

- the WebSocket upgrade (`uid` header)
- `GET /api/v1/users/subscribe/room/:rid`
- `GET /api/v1/users/unsubscribe/room/:rid`
- `GET /api/v1/messages/room/:rid`

Admin endpoints are unaffected — they are authenticated with the admin key, and
the admin is trusted to name any uid.

With **no** secret set, the server logs a loud SECURITY warning at startup unless
`SL_TRUST_UID_HEADER=1` is set to certify a trusted-backend deployment.

## Token format

```
token = "<expiry-unix>.<hex hmac_sha256(secret, uid + '.' + expiry-unix)>"
```

- `expiry-unix` — Unix seconds after which the token is rejected.
- The HMAC binds the token to a specific `uid`, so a token minted for `alice`
  cannot be used to connect as `bob`.
- Comparison is constant-time.

## Minting (backend, at login)

Python:

```python
import time, hmac, hashlib

def mint_token(uid: str, secret: str, ttl_seconds: int = 3600) -> str:
    expiry = int(time.time()) + ttl_seconds
    sig = hmac.new(secret.encode(), f"{uid}.{expiry}".encode(), hashlib.sha256).hexdigest()
    return f"{expiry}.{sig}"
```

Node.js:

```js
const crypto = require("crypto");

function mintToken(uid, secret, ttlSeconds = 3600) {
  const expiry = Math.floor(Date.now() / 1000) + ttlSeconds;
  const sig = crypto.createHmac("sha256", secret).update(`${uid}.${expiry}`).digest("hex");
  return `${expiry}.${sig}`;
}
```

The client then sends the token in the `token` header on the WebSocket upgrade
and on any `uid`-bearing REST call. Give tokens a short TTL and re-mint as needed;
the server only checks the signature and expiry, it keeps no token state.

See `tests/token_test.py` for the enforcement matrix and a runnable reference.
