"""Process-local authentication throttling (shared store needed for multiworker)."""
import math
import threading
import time
from collections import deque

from fastapi import HTTPException, Request

WINDOW = 900
MAX_IDENTITIES = 10_000
_attempts = {}
_failures = {}
_lock = threading.Lock()


def _trim(bucket, now):
    while bucket and bucket[0] <= now - WINDOW:
        bucket.popleft()


def _get_bucket(store, key, now):
    if key not in store:
        if len(store) >= MAX_IDENTITIES:
            # Prune expired identities first; cap state even when attackers
            # continuously vary usernames or connect from many peers.
            for identity, bucket in list(store.items()):
                _trim(bucket, now)
                if not bucket:
                    del store[identity]
            if len(store) >= MAX_IDENTITIES:
                oldest = min(store, key=lambda identity: store[identity][-1])
                del store[oldest]
        store[key] = deque()
    bucket = store[key]
    _trim(bucket, now)
    return bucket


def check(request: Request, username: str):
    # Never trust forwarded headers unless an explicitly trusted proxy handles them.
    ip = request.client.host if request.client else "unknown"
    name = username.strip().casefold()
    now = time.monotonic()
    with _lock:
        ip_bucket = _get_bucket(_attempts, ip, now)
        user_bucket = _get_bucket(_failures, name, now)
        blocked = (ip_bucket if len(ip_bucket) >= 20 else
                   user_bucket if len(user_bucket) >= 5 else None)
        if blocked is not None:
            retry = max(1, math.ceil(WINDOW - (now - blocked[0])))
            raise HTTPException(429, "Too many authentication attempts", headers={"Retry-After": str(retry)})
        ip_bucket.append(now)
    return name


def failed(name: str):
    with _lock:
        now = time.monotonic()
        _get_bucket(_failures, name, now).append(now)


def succeeded(name: str):
    with _lock:
        _failures.pop(name, None)
