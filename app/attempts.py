"""Failed-login counters for usernames that do not exist (or are disabled).

The login screen shows "N attempts remaining". If only REAL accounts had a counter, that message
would reveal which usernames exist. So unknown and disabled usernames get the same counter and
the same lockout behaviour, and every username produces identical messages."""
import math
import threading
import time

from .config import settings

MAX_TRACKED = 10_000


class GhostAttempts:
    def __init__(self):
        self._d: dict[str, dict] = {}
        self._lock = threading.Lock()

    def locked_minutes(self, name: str) -> int:
        """Minutes of lockout left for this name, or 0."""
        now = time.time()
        with self._lock:
            e = self._d.get(name)
            if not e:
                return 0
            if e["until"] > now:
                return max(1, math.ceil((e["until"] - now) / 60))
            if e["until"]:                       # lock expired: forget it
                del self._d[name]
            return 0

    def fail(self, name: str) -> tuple[int, bool]:
        """Records a failure. Returns (failures_so_far, locked_now)."""
        now = time.time()
        with self._lock:
            if len(self._d) >= MAX_TRACKED:
                self._d = {k: v for k, v in self._d.items() if v["until"] > now or v["count"] > 0}
                if len(self._d) >= MAX_TRACKED * 2:      # flood protection: stop growing
                    return 1, False
            e = self._d.setdefault(name, {"count": 0, "until": 0.0})
            e["count"] += 1
            if e["count"] >= settings.max_failed_attempts:
                e["count"] = 0
                e["until"] = now + settings.lockout_minutes * 60
                return settings.max_failed_attempts, True
            return e["count"], False

    def clear(self):
        with self._lock:
            self._d.clear()


ghosts = GhostAttempts()
