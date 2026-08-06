"""TopN 单元测试 — 通用 Top N 计数器。"""

from __future__ import annotations

from app.flow.topn import TopN


class TestTopN:
    def test_empty(self):
        t = TopN(capacity=5)
        assert t.top() == []
        assert t.top(3) == []

    def test_add_and_top(self):
        t = TopN(capacity=10)
        t.add("a")
        t.add("a")
        t.add("b")
        assert t.top(2) == [("a", 2), ("b", 1)]

    def test_top_respects_capacity(self):
        t = TopN(capacity=2)
        for k in ["a", "b", "c", "d"]:
            t.add(k)
        top = t.top()
        assert len(top) == 2

    def test_top_with_n_limit(self):
        t = TopN(capacity=10)
        for k in ["a", "b", "c"]:
            t.add(k)
        assert len(t.top(2)) == 2
        assert len(t.top()) == 3

    def test_add_with_value(self):
        t = TopN(capacity=10)
        t.add("x", value=5)
        t.add("x", value=3)
        assert t.top(1) == [("x", 8)]

    def test_reset(self):
        t = TopN(capacity=10)
        t.add("a", value=10)
        t.reset()
        assert t.top() == []

    def test_sorted_desc(self):
        """top() 应按计数降序。"""
        t = TopN(capacity=10)
        t.add("low", value=1)
        t.add("high", value=100)
        t.add("mid", value=50)
        assert t.top() == [("high", 100), ("mid", 50), ("low", 1)]
