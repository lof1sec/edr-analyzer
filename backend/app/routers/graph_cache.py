"""Process-local LRU + TTL cache for generated graph payloads.

Building a graph re-parses every stored event, which is the most expensive
operation in the app. Caching the result per dataset keeps repeated opens (and
the lazy raw-log / search endpoints) cheap.

The cache is intentionally process-local and bounded: it never grows without
limit, entries expire after ``GRAPH_CACHE_TTL_SECONDS`` (so a dataset edited
out-of-band eventually refreshes), and it is invalidated whenever a dataset is
deleted or re-uploaded.
"""
import os
import threading
import time
from collections import OrderedDict

_MAX_ENTRIES = max(1, int(os.getenv("GRAPH_CACHE_SIZE", "4")))
# 0 disables expiry.
_TTL_SECONDS = float(os.getenv("GRAPH_CACHE_TTL_SECONDS", "300"))

# dataset_id -> (stored_at_monotonic, payload)
_cache: "OrderedDict[int, tuple[float, dict]]" = OrderedDict()
_lock = threading.Lock()


def _expired(stored_at: float) -> bool:
    return _TTL_SECONDS > 0 and (time.monotonic() - stored_at) > _TTL_SECONDS


def get(dataset_id: int):
    """Return a fresh cached payload for ``dataset_id`` or ``None``.

    Accessing an entry marks it as most-recently-used; expired entries are
    dropped on access.
    """
    with _lock:
        entry = _cache.get(dataset_id)
        if entry is None:
            return None
        stored_at, payload = entry
        if _expired(stored_at):
            del _cache[dataset_id]
            return None
        _cache.move_to_end(dataset_id)
        return payload


def put(dataset_id: int, payload: dict) -> None:
    """Store ``payload`` for ``dataset_id``, evicting the least-recently-used."""
    with _lock:
        _cache[dataset_id] = (time.monotonic(), payload)
        _cache.move_to_end(dataset_id)
        while len(_cache) > _MAX_ENTRIES:
            _cache.popitem(last=False)


def invalidate(dataset_id: int | None = None) -> None:
    """Drop one dataset's payload, or the whole cache when ``dataset_id`` is None."""
    with _lock:
        if dataset_id is None:
            _cache.clear()
        else:
            _cache.pop(dataset_id, None)
