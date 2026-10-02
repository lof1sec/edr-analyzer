"""Process-local LRU cache for generated graph payloads.

Building a graph re-parses every stored event, which is the most expensive
operation in the app. Caching the result per dataset keeps repeated opens (and
the lazy raw-log endpoint) cheap.

The cache is intentionally process-local and bounded: it never grows without
limit, and it is invalidated whenever a dataset is deleted or re-uploaded.
"""
import os
import threading
from collections import OrderedDict

_MAX_ENTRIES = max(1, int(os.getenv("GRAPH_CACHE_SIZE", "4")))

_cache: "OrderedDict[int, dict]" = OrderedDict()
_lock = threading.Lock()


def get(dataset_id: int):
    """Return the cached payload for ``dataset_id`` or ``None``.

    Accessing an entry marks it as most-recently-used.
    """
    with _lock:
        payload = _cache.get(dataset_id)
        if payload is not None:
            _cache.move_to_end(dataset_id)
        return payload


def put(dataset_id: int, payload: dict) -> None:
    """Store ``payload`` for ``dataset_id``, evicting the least-recently-used."""
    with _lock:
        _cache[dataset_id] = payload
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
