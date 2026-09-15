"""Tests for reconpro.http_layer.RateLimiter."""

import sys
import os
import time
import unittest
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.http_layer import RateLimiter


class TestRateLimiterConstructor(unittest.TestCase):
    """Test RateLimiter constructor sets correct interval."""

    def test_default_interval(self):
        rl = RateLimiter()
        self.assertAlmostEqual(rl._min_interval, 0.1, places=3)

    def test_custom_rate(self):
        rl = RateLimiter(max_per_second=2.0)
        self.assertAlmostEqual(rl._min_interval, 0.5, places=3)

    def test_high_rate_small_interval(self):
        rl = RateLimiter(max_per_second=100.0)
        self.assertAlmostEqual(rl._min_interval, 0.01, places=3)

    def test_has_lock(self):
        rl = RateLimiter()
        self.assertIsInstance(rl._lock, type(threading.Lock()))


class TestRateLimiterAcquire(unittest.TestCase):
    """Test RateLimiter.acquire works without blocking for slow rates."""

    def test_first_acquire_no_delay(self):
        rl = RateLimiter(max_per_second=1000.0)
        start = time.monotonic()
        rl.acquire()
        elapsed = time.monotonic() - start
        # Should complete nearly instantly for 1000 req/s
        self.assertLess(elapsed, 0.1)

    def test_second_acquire_after_interval(self):
        rl = RateLimiter(max_per_second=100.0)  # 10ms interval
        rl.acquire()  # First call
        start = time.monotonic()
        rl.acquire()  # Second call should wait
        elapsed = time.monotonic() - start
        # Should wait roughly 10ms
        self.assertGreaterEqual(elapsed, 0.005)

    def test_very_slow_rate(self):
        rl = RateLimiter(max_per_second=1.0)  # 1s interval
        rl.acquire()
        start = time.monotonic()
        rl.acquire()
        elapsed = time.monotonic() - start
        # Should wait roughly 1s
        self.assertGreaterEqual(elapsed, 0.9)


class TestRateLimiterThreadSafety(unittest.TestCase):
    """Basic concurrent acquire test."""

    def test_concurrent_acquires_dont_crash(self):
        rl = RateLimiter(max_per_second=100.0)
        errors = []

        def worker():
            try:
                for _ in range(10):
                    rl.acquire()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [])

    def test_concurrent_rate_limiting(self):
        rl = RateLimiter(max_per_second=100.0)  # 10ms interval
        rl.acquire()  # Prime the limiter

        results = []
        lock = threading.Lock()

        def worker():
            start = time.monotonic()
            rl.acquire()
            elapsed = time.monotonic() - start
            with lock:
                results.append(elapsed)

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        # At least one thread should have waited
        self.assertTrue(any(r > 0.005 for r in results))


if __name__ == "__main__":
    unittest.main()
