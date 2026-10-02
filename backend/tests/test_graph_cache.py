import time

from app.routers import graph_cache


def setup_function():
    graph_cache.invalidate()


def test_put_get_and_invalidate():
    graph_cache.put(1, {"elements": {}})
    assert graph_cache.get(1) == {"elements": {}}

    graph_cache.invalidate(1)
    assert graph_cache.get(1) is None


def test_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(graph_cache, "_MAX_ENTRIES", 2)
    graph_cache.put(1, {"a": 1})
    graph_cache.put(2, {"a": 2})
    graph_cache.put(3, {"a": 3})

    # The least-recently-used entry is evicted first.
    assert graph_cache.get(1) is None
    assert graph_cache.get(2) == {"a": 2}
    assert graph_cache.get(3) == {"a": 3}


def test_expired_entries_are_dropped(monkeypatch):
    monkeypatch.setattr(graph_cache, "_TTL_SECONDS", 0.01)
    graph_cache.put(1, {"a": 1})
    time.sleep(0.02)
    assert graph_cache.get(1) is None


def test_get_marks_entry_as_recently_used(monkeypatch):
    monkeypatch.setattr(graph_cache, "_MAX_ENTRIES", 2)
    graph_cache.put(1, {"a": 1})
    graph_cache.put(2, {"a": 2})

    # Touching 1 makes 2 the least-recently-used, so 2 is evicted next.
    graph_cache.get(1)
    graph_cache.put(3, {"a": 3})

    assert graph_cache.get(1) == {"a": 1}
    assert graph_cache.get(2) is None
