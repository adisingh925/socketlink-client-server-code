#!/usr/bin/env python3
"""
Connection-token enforcement test, and the reference for minting tokens.

Token format (what your backend produces, one per user at login):
    token = "<expiry-unix>.<hex hmac_sha256(secret, uid + '.' + expiry-unix)>"

The server must run with SL_CONNECTION_TOKEN_SECRET set to the same secret.

Usage: token_test.py [host] [port] [secret]
"""
import base64
import hashlib
import hmac
import http.client
import os
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
SECRET = sys.argv[3] if len(sys.argv) > 3 else "s3cret"
CLIENT_KEY = "change-me-client-key"

failures = []


def mint(uid, ttl=3600, secret=SECRET):
    """Mint a token for `uid`. THIS is the snippet a backend runs at login."""
    expiry = int(time.time()) + ttl
    msg = f"{uid}.{expiry}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return f"{expiry}.{sig}"


def ws_upgrade(uid, token):
    """Return the HTTP status line of a WS upgrade attempt."""
    s = socket.create_connection((HOST, PORT), timeout=5)
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
               f"api-key: {CLIENT_KEY}\r\nuid: {uid}\r\n")
        if token is not None:
            req += f"token: {token}\r\n"
        req += "\r\n"
        s.sendall(req.encode())
        return s.recv(256).decode("latin1").split("\r\n", 1)[0]
    finally:
        s.close()


def rest_subscribe(uid, token):
    """Status of a REST subscribe (enforcement must apply beyond the upgrade)."""
    c = http.client.HTTPConnection(HOST, PORT, timeout=5)
    try:
        headers = {"api-key": CLIENT_KEY, "uid": uid}
        if token is not None:
            headers["token"] = token
        c.request("GET", "/api/v1/users/subscribe/room/pub-x", headers=headers)
        r = c.getresponse()
        r.read()
        return r.status
    finally:
        c.close()


def check(label, got, want):
    ok = (got == want) or (isinstance(want, (list, tuple)) and got in want)
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: got {got!r}, want {want!r}")
    if not ok:
        failures.append(label)


print(f"token enforcement against {HOST}:{PORT}\n")

good = mint("alice")
forged = f"{int(time.time()) + 3600}." + "0" * 64
expired = mint("alice", ttl=-10)
wrong_uid = mint("bob")  # valid token, but for a different uid

print("WS upgrade")
check("valid token -> 101", "101" in ws_upgrade("alice", good) and "101", "101")
check("missing token -> 401", ws_upgrade("alice", None), "HTTP/1.1 401 Unauthorized")
check("forged token -> 401", ws_upgrade("alice", forged), "HTTP/1.1 401 Unauthorized")
check("expired token -> 401", ws_upgrade("alice", expired), "HTTP/1.1 401 Unauthorized")
check("token for other uid -> 401", ws_upgrade("alice", wrong_uid), "HTTP/1.1 401 Unauthorized")

print("\nREST subscribe (enforcement beyond the upgrade)")
# subscribe needs a live connection for the uid; unknown uid returns 404 AFTER the
# token check passes, and 401 when the token fails — so we assert the token gate.
check("missing token -> 401", rest_subscribe("ghost", None), 401)
check("forged token -> 401", rest_subscribe("ghost", forged), 401)
check("valid token -> not 401 (404 unknown uid)", rest_subscribe("ghost", mint("ghost")), 404)

print(f"\n{len(failures)} failures")
sys.exit(1 if failures else 0)
