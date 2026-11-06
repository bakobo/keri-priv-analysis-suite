"""Place what the stack did at wall-clock times onto the scenario's clock.

The driver records the wall-clock time each action started. Anything stamped at a wall-clock time
belongs to the latest action started by then, and takes that action's scenario time: a log line
written while the third issuance ran is placed at the third issuance's scenario time. Provisioning
is placed the day before issuance opens, as the generator places it. KERIA stamps its own log lines
to the second, so a log line is compared with each action's start truncated to the second.
"""

from __future__ import annotations

from bisect import bisect_right
from datetime import datetime
from math import floor

from .plan import Plan

PROVISIONING = -86400.0


class Clock:
    def __init__(self, timeline: list, plan: Plan):
        scenario = {"provision": lambda n: PROVISIONING,
                    "issue": lambda n: plan.issuance[n].time,
                    "present": lambda n: plan.showings[n].time}
        steps = sorted((wall, scenario[kind](n)) for kind, n, wall in timeline)
        self.walls = [wall for wall, _ in steps]
        self.seconds = [floor(wall) for wall, _ in steps]
        self.times = [t for _, t in steps]

    def at(self, wall: float) -> float:
        """The scenario time of something stamped at a precise wall-clock time."""
        return self._pick(bisect_right(self.walls, wall))

    def at_second(self, wall: float) -> float:
        """The scenario time of a log line stamped to the second."""
        return self._pick(bisect_right(self.seconds, floor(wall)))

    def at_stamp(self, stamp: str) -> float:
        """The scenario time of an RFC 3339 stamp, such as an exchange message's dt."""
        return self.at(datetime.fromisoformat(stamp).timestamp())

    def _pick(self, n: int) -> float:
        return self.times[max(n - 1, 0)]
