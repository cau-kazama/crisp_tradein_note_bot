#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import time
from urllib import request


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Send sample Crisp webhook payload to local service")
    p.add_argument("--url", default="http://localhost:8080/crisp/webhook")
    p.add_argument("--website-id", default="40846966-0f0d-45f6-b72b-8a24bf268953")
    p.add_argument("--session-id", default="session_test_123")
    p.add_argument("--secret", default="", help="Crisp hook secret (if signature enabled)")
    p.add_argument("--event", default="message:send")
    p.add_argument("--from-actor", default="user")
    p.add_argument("--message-type", default="text")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    payload = {
        "website_id": args.website_id,
        "event": args.event,
        "data": {
            "website_id": args.website_id,
            "session_id": args.session_id,
            "from": args.from_actor,
            "type": args.message_type,
            "content": "hello",
            "fingerprint": 123456789,
            "timestamp": int(time.time() * 1000),
        },
        "timestamp": int(time.time() * 1000),
    }

    body = json.dumps(payload, separators=(",", ":"))
    headers = {"Content-Type": "application/json"}

    if args.secret:
        ts = str(int(time.time()))
        msg = f"[{ts};{body}]".encode("utf-8")
        sig = hmac.new(args.secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        headers["X-Crisp-Request-Timestamp"] = ts
        headers["X-Crisp-Signature"] = sig

    req = request.Request(args.url, data=body.encode("utf-8"), headers=headers, method="POST")
    with request.urlopen(req, timeout=15) as resp:
        print(resp.status)
        print(resp.read().decode("utf-8", errors="replace"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
