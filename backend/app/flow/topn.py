"""Top N 实时计算。"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field


@dataclass
class TopN:
    """通用 Top N 计数器。"""
    capacity: int = 20
    _counter: Counter = field(default_factory=Counter)

    def add(self, key: str, value: int = 1) -> None:
        self._counter[key] += value

    def top(self, n: int | None = None) -> list[tuple[str, int]]:
        return self._counter.most_common(n or self.capacity)

    def reset(self) -> None:
        self._counter.clear()
