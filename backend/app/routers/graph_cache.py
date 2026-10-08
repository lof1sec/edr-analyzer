"""Process-local LRU + TTL cache for generated graph payloads.

Building a graph re-parses every stored event, which is the most expensive
operation in the app. Caching the result per dataset keeps repeated opens (and
the lazy raw-log / search endpoints) cheap.

Entries are keyed by ``(dataset_id, from_ms, to_ms)`` so a time-filtered graph is
cached independently of the unfiltered one. The cache is intentionally
process-local and bounded: it never grows without limit, entries expire after
``GRAPH_CACHE_TTL_SECONDS`` (so a dataset edited out-of-band eventually
refreshes), and it is invalidated whenever a dataset is deleted or re-uploaded.
"""
import os
import threading
import time
from collections import OrderedDict

_MAX_ENTRIES = max(1, int(os.getenv("GRAPH_CACHE_SIZE", "4")))
# 0 disables expiry.
_TTL_SECONDS = float(os.getenv("GRAPH_CACHE_TTL_SECONDS", "300"))

# (dataset_id, from_ms, to_ms) -> (stored_at_monotonic, payload)
_cache: "OrderedDict[tuple, tuple[float, dict]]" = OrderedDict()
_lock = threading.Lock()


def _expired(stored_at: float) -> bool:
    return _TTL_SECONDS > 0 and (time.monotonic() - stored_at) > _TTL_SECONDS


def get(key):
    """Return a fresh cached payload for ``key`` or ``None``.

    Accessing an entry marks it as most-recently-used; expired entries are
    dropped on access.
    """
    with _lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        stored_at, payload = entry
        if _expired(stored_at):
            del _cache[key]
            return None
        _cache.move_to_end(key)
        return payload


def put(key, payload) -> None:
    """Store ``payload`` for ``key``, evicting the least-recently-used."""
    with _lock:
        _cache[key] = (time.monotonic(), payload)
        _cache.move_to_end(key)
        while len(_cache) > _MAX_ENTRIES:
            _cache.popitem(last=False)


def invalidate(dataset_id: int | None = None) -> None:
    """Drop every entry for ``dataset_id``, or the whole cache when ``None``.

    Keys are ``(dataset_id, from_ms, to_ms)``, so invalidating a dataset removes
    its unfiltered graph *and* every cached time range in one pass.
    """
    with _lock:
        if dataset_id is None:
            _cache.clear()
        else:
            for key in [key for key in _cache if key[0] == dataset_id]:
                del _cache[key]
