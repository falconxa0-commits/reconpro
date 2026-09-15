"""Proxy pool management for distributed scanning — ReconPro v7.0.

Manages proxy lifecycle, rotation strategies, health checking,
Tor circuit integration, and proxy-aware HTTP probing.

Pure stdlib — no external dependencies.

Exports:
    Proxy, ProxyPool, RotationStrategy, TorProxyManager,
    proxy_probe, load_default_pool
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Proxy Dataclass ──────────────────────────────────────────────────────


@dataclass
class Proxy:
    """Single proxy endpoint with health metadata."""

    url: str
    protocol: str  # 'http' | 'https' | 'socks5'
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    country: Optional[str] = None
    last_check: float = 0.0
    is_alive: bool = True
    avg_response_time: float = 0.0
    fail_count: int = 0
    success_count: int = 0

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "country": self.country,
            "last_check": self.last_check,
            "is_alive": self.is_alive,
            "avg_response_time": self.avg_response_time,
            "fail_count": self.fail_count,
            "success_count": self.success_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Proxy:
        return cls(
            url=data["url"],
            protocol=data["protocol"],
            host=data["host"],
            port=data["port"],
            username=data.get("username"),
            password=data.get("password"),
            country=data.get("country"),
            last_check=data.get("last_check", 0.0),
            is_alive=data.get("is_alive", True),
            avg_response_time=data.get("avg_response_time", 0.0),
            fail_count=data.get("fail_count", 0),
            success_count=data.get("success_count", 0),
        )


# ── Proxy String Parser ──────────────────────────────────────────────────


def _parse_proxy_str(proxy_str: str) -> Proxy:
    """Parse a proxy URL string into a Proxy object.

    Accepts formats:
        http://host:port
        http://user:pass@host:port
        socks5://host:port
    """
    proxy_str = proxy_str.strip()
    if not proxy_str:
        raise ValueError("Empty proxy string")

    parsed = urllib.parse.urlparse(proxy_str)
    protocol = parsed.scheme.lower() if parsed.scheme else "http"
    if protocol not in ("http", "https", "socks5", "socks4"):
        protocol = "http"
    if protocol == "socks4":
        protocol = "socks5"

    host = parsed.hostname or ""
    port = parsed.port or 8080
    username = parsed.username
    password = parsed.password

    # Reconstruct canonical URL
    url = f"{protocol}://"
    if username and password:
        url += f"{username}:{password}@"
    url += f"{host}:{port}"

    return Proxy(
        url=url,
        protocol=protocol,
        host=host,
        port=port,
        username=username,
        password=password,
    )


# ── Rotation Strategies ──────────────────────────────────────────────────


class RotationStrategy(Enum):
    """Available proxy rotation strategies."""
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    LEAST_CONNECTIONS = "least_connections"
    GEO_DISTRIBUTED = "geo_distributed"


class _BaseStrategy:
    """Base class for rotation strategies."""

    def __init__(self, pool: list[Proxy]) -> None:
        self.pool = pool

    def next(self) -> Proxy | None:
        raise NotImplementedError


class _RoundRobin(_BaseStrategy):
    """Cycle through proxies in order, skipping dead ones."""

    def __init__(self, pool: list[Proxy]) -> None:
        super().__init__(pool)
        self._index: int = 0

    def next(self) -> Proxy | None:
        alive = [p for p in self.pool if p.is_alive]
        if not alive:
            return None
        proxy = alive[self._index % len(alive)]
        self._index += 1
        return proxy


class _Random(_BaseStrategy):
    """Pick a random alive proxy each time."""

    def next(self) -> Proxy | None:
        alive = [p for p in self.pool if p.is_alive]
        if not alive:
            return None
        return random.choice(alive)


class _LeastConnections(_BaseStrategy):
    """Prefer the proxy with the fewest active in-flight uses.

    Call ``acquire(proxy)`` before a request and ``release(proxy)``
    after it completes so the counter stays accurate.
    """

    def __init__(self, pool: list[Proxy]) -> None:
        super().__init__(pool)
        self._active: dict[str, int] = {p.url: 0 for p in pool}

    def acquire(self, proxy: Proxy) -> None:
        self._active[proxy.url] = self._active.get(proxy.url, 0) + 1

    def release(self, proxy: Proxy) -> None:
        self._active[proxy.url] = max(0, self._active.get(proxy.url, 1) - 1)

    def next(self) -> Proxy | None:
        alive = [p for p in self.pool if p.is_alive]
        if not alive:
            return None
        alive.sort(key=lambda p: self._active.get(p.url, 0))
        return alive[0]


class _GeoDistributed(_BaseStrategy):
    """Cycle through proxies from different countries."""

    def __init__(self, pool: list[Proxy]) -> None:
        super().__init__(pool)
        self._country_index: int = 0

    def next(self) -> Proxy | None:
        alive = [p for p in self.pool if p.is_alive]
        if not alive:
            return None

        by_country: dict[str, list[Proxy]] = {}
        for p in alive:
            key = p.country or "unknown"
            by_country.setdefault(key, []).append(p)

        countries = list(by_country.keys())
        country = countries[self._country_index % len(countries)]
        self._country_index += 1

        proxies = by_country[country]
        return proxies[0]


def _create_strategy(name: str, pool: list[Proxy]) -> _BaseStrategy:
    """Factory: instantiate a rotation strategy by name."""
    registry: dict[str, type[_BaseStrategy]] = {
        "round_robin": _RoundRobin,
        "random": _Random,
        "least_connections": _LeastConnections,
        "geo_distributed": _GeoDistributed,
    }
    cls = registry.get(name)
    if cls is None:
        raise ValueError(
            f"Unknown rotation strategy: {name!r}. "
            f"Choose from: {', '.join(registry)}"
        )
    return cls(pool)


# ── Proxy-Aware HTTP Probe ───────────────────────────────────────────────


def proxy_probe(url: str, proxy: Proxy, timeout: int = 10) -> dict:
    """Make an HTTP GET through *proxy* and return timing / status info.

    Returns:
        {
            "ok": bool,
            "status": int,
            "proxy_ip": str | None,
            "response_time": float,
        }
    """
    result: dict = {
        "ok": False,
        "status": 0,
        "proxy_ip": None,
        "response_time": 0.0,
    }

    start = time.monotonic()
    handler = urllib.request.ProxyHandler({"http": proxy.url, "https": proxy.url})
    opener = urllib.request.build_opener(handler)

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ReconPro/7.0 (Security Scanner)"},
        )
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            result["status"] = resp.status
            # Try to extract origin IP (httpbin.org/ip returns {"origin":"..."})
            try:
                data = json.loads(body)
                result["proxy_ip"] = data.get("origin", "")
            except (json.JSONDecodeError, KeyError):
                result["proxy_ip"] = ""
            result["ok"] = 200 <= resp.status < 400
    except Exception:
        pass

    result["response_time"] = round(time.monotonic() - start, 4)
    return result


# ── Proxy Pool ───────────────────────────────────────────────────────────


class ProxyPool:
    """Thread-safe proxy pool with health checking and rotation.

    Usage::

        pool = ProxyPool(["http://1.2.3.4:8080", "socks5://user:pw@5.6.7.8:1080"])
        await pool.health_check()
        proxy = pool.get_proxy("random")
        if proxy:
            result = proxy_probe("https://example.com", proxy)
            if result["ok"]:
                pool.report_success(proxy.url, result["response_time"])
            else:
                pool.report_dead(proxy.url)
    """

    def __init__(
        self,
        proxies: list[str] | None = None,
        config_path: str = "~/.reconpro/proxies.json",
    ) -> None:
        self._proxies: list[Proxy] = []
        self._config_path = Path(config_path).expanduser()
        self._lock = threading.Lock()
        self._strategy_name: str = "round_robin"
        self._strategy: _BaseStrategy | None = None

        if proxies:
            self.add_proxies(proxies)

    # -- helpers --

    @property
    def _alive(self) -> list[Proxy]:
        return [p for p in self._proxies if p.is_alive]

    def _rebuild_strategy(self) -> None:
        self._strategy = _create_strategy(self._strategy_name, self._proxies)

    # -- loading --

    def load_from_file(self, path: str | Path) -> int:
        """Load proxies from a text file (one URL per line, ``#`` comments)."""
        path = Path(path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Proxy file not found: {path}")

        count = 0
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        self.add_proxy(line)
                        count += 1
                    except ValueError:
                        continue
        logger.info("Loaded %d proxies from %s", count, path)
        return count

    def load_from_url(self, url: str) -> int:
        """Fetch a proxy list from a remote HTTP URL."""
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ReconPro/7.0 (Security Scanner)"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read().decode("utf-8")
        except Exception as exc:
            raise ConnectionError(f"Failed to fetch proxy list from {url}: {exc}") from exc

        count = 0
        for line in data.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    self.add_proxy(line)
                    count += 1
                except ValueError:
                    continue
        logger.info("Loaded %d proxies from %s", count, url)
        return count

    # -- adding --

    def add_proxy(self, proxy_str: str) -> Proxy:
        """Parse and add a single proxy string. Returns the Proxy object."""
        proxy = _parse_proxy_str(proxy_str)
        with self._lock:
            for existing in self._proxies:
                if existing.host == proxy.host and existing.port == proxy.port:
                    return existing
            self._proxies.append(proxy)
            self._rebuild_strategy()
        return proxy

    def add_proxies(self, proxy_list: list[str]) -> int:
        """Add multiple proxies. Returns count of newly added."""
        count = 0
        for ps in proxy_list:
            try:
                self.add_proxy(ps)
                count += 1
            except ValueError:
                continue
        return count

    # -- health check --

    async def health_check(self, max_workers: int = 20) -> dict:
        """Async health check against httpbin.org/ip (5 s timeout).

        Dead proxies (3+ consecutive fails) are marked inactive.
        Returns summary dict: {checked, alive, dead, removed}.
        """
        results = {"checked": 0, "alive": 0, "dead": 0, "removed": 0}
        proxies_to_check = list(self._proxies)
        results["checked"] = len(proxies_to_check)

        def _check_one(proxy: Proxy) -> tuple[Proxy, bool, float]:
            try:
                r = proxy_probe("https://httpbin.org/ip", proxy, timeout=5)
                return proxy, r["ok"], r["response_time"]
            except Exception:
                return proxy, False, 0.0

        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            tasks = [
                loop.run_in_executor(pool, _check_one, p) for p in proxies_to_check
            ]
            outcomes = await asyncio.gather(*tasks)

        for proxy, alive, resp_time in outcomes:
            if alive:
                proxy.is_alive = True
                proxy.last_check = time.time()
                proxy.fail_count = 0
                proxy.success_count += 1
                if proxy.avg_response_time > 0:
                    proxy.avg_response_time = (
                        proxy.avg_response_time + resp_time
                    ) / 2
                else:
                    proxy.avg_response_time = resp_time
                results["alive"] += 1
            else:
                proxy.fail_count += 1
                if proxy.fail_count >= 3:
                    proxy.is_alive = False
                    results["removed"] += 1
                results["dead"] += 1

        self._rebuild_strategy()
        logger.info(
            "Health check done: %d alive, %d dead, %d removed",
            results["alive"],
            results["dead"],
            results["removed"],
        )
        return results

    # -- retrieval --

    def get_proxy(self, strategy: str = "round_robin") -> Proxy | None:
        """Return the next proxy according to *strategy*.

        Strategies: round_robin, random, least_connections, geo_distributed.
        """
        if strategy != self._strategy_name:
            self._strategy_name = strategy
            self._rebuild_strategy()
        if self._strategy is None:
            self._rebuild_strategy()
        return self._strategy.next() if self._strategy else None

    def rotate(self) -> Proxy | None:
        """Cycle past the current proxy and return the next one.

        The current head-of-queue proxy is moved to the tail so it
        will not be returned again until all others have been tried.
        """
        if not self._proxies:
            return None
        with self._lock:
            if self._proxies:
                self._proxies.append(self._proxies.pop(0))
        self._rebuild_strategy()
        return self.get_proxy()

    # -- reporting --

    def report_dead(self, proxy_url: str) -> None:
        """Mark a proxy as failed. Removes it after 3 consecutive failures."""
        with self._lock:
            for proxy in self._proxies:
                if proxy.url == proxy_url:
                    proxy.fail_count += 1
                    if proxy.fail_count >= 3:
                        proxy.is_alive = False
                        logger.warning("Proxy removed (3 failures): %s", proxy_url)
                    break
        self._rebuild_strategy()

    def report_success(self, proxy_url: str, response_time: float = 0) -> None:
        """Mark a proxy as healthy and update its rolling response time."""
        with self._lock:
            for proxy in self._proxies:
                if proxy.url == proxy_url:
                    proxy.success_count += 1
                    proxy.fail_count = 0
                    proxy.last_check = time.time()
                    if response_time > 0:
                        if proxy.avg_response_time > 0:
                            proxy.avg_response_time = (
                                proxy.avg_response_time + response_time
                            ) / 2
                        else:
                            proxy.avg_response_time = response_time
                    break
        self._rebuild_strategy()

    # -- stats --

    def stats(self) -> dict:
        """Return pool statistics."""
        total = len(self._proxies)
        alive = len(self._alive)
        dead = total - alive

        by_country: dict[str, int] = {}
        total_rt = 0.0
        rt_count = 0
        for p in self._proxies:
            if p.is_alive:
                key = p.country or "unknown"
                by_country[key] = by_country.get(key, 0) + 1
            if p.avg_response_time > 0:
                total_rt += p.avg_response_time
                rt_count += 1

        return {
            "total": total,
            "alive": alive,
            "dead": dead,
            "by_country": by_country,
            "avg_response_time": round(total_rt / rt_count, 4) if rt_count else 0.0,
        }

    # -- persistence --

    def save(self) -> None:
        """Persist the current pool state to *config_path*."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        data = [p.to_dict() for p in self._proxies]
        tmp = self._config_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        tmp.replace(self._config_path)
        logger.debug("Saved %d proxies to %s", len(data), self._config_path)

    def load(self) -> int:
        """Load pool state from *config_path*. Returns count loaded."""
        if not self._config_path.exists():
            return 0
        with open(self._config_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self._proxies = [Proxy.from_dict(d) for d in data]
        self._rebuild_strategy()
        logger.debug("Loaded %d proxies from %s", len(self._proxies), self._config_path)
        return len(self._proxies)

    # -- dunder --

    def __len__(self) -> int:
        return len(self._proxies)

    def __repr__(self) -> str:
        return f"ProxyPool(proxies={len(self._proxies)}, alive={len(self._alive)})"


# ── TOR Integration ──────────────────────────────────────────────────────


class TorProxyManager:
    """Manage a local Tor instance for anonymous scanning.

    Expects Tor running with:
      - SOCKS5 proxy on 127.0.0.1:9050
      - Control port on 127.0.0.1:9051

    Usage::

        tor = TorProxyManager()
        if tor.check_tor_available():
            tor.new_circuit()
            info = tor.verify_new_ip()
            proxy = tor.get_tor_session()
    """

    DEFAULT_SOCKS_HOST = "127.0.0.1"
    DEFAULT_SOCKS_PORT = 9050
    DEFAULT_CONTROL_PORT = 9051

    def __init__(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        control_port: int = 9051,
    ) -> None:
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_port = control_port
        self._last_ip: str | None = None

    def check_tor_available(self) -> bool:
        """Return True if the Tor SOCKS proxy is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            rc = sock.connect_ex((self.socks_host, self.socks_port))
            sock.close()
            return rc == 0
        except OSError:
            return False

    def new_circuit(self) -> bool:
        """Request a new Tor circuit via the control port (NEWNYM signal).

        Sends AUTHENTICATE then SIGNAL NEWNYM over the Tor control
        protocol.  Returns True on success.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.socks_host, self.control_port))

            # Read the initial 250 greeting
            greeting = sock.recv(1024).decode("utf-8", errors="replace")
            if "250" not in greeting:
                sock.close()
                return False

            # Authenticate with empty password
            sock.sendall(b'AUTHENTICATE ""\r\n')
            auth_resp = sock.recv(1024).decode("utf-8", errors="replace")
            if "250" not in auth_resp:
                sock.sendall(b"AUTHENTICATE\r\n")
                auth_resp = sock.recv(1024).decode("utf-8", errors="replace")
                if "250" not in auth_resp:
                    sock.close()
                    return False

            # Request new identity
            sock.sendall(b"SIGNAL NEWNYM\r\n")
            signal_resp = sock.recv(1024).decode("utf-8", errors="replace")
            sock.close()

            success = "250" in signal_resp
            if success:
                logger.info("Tor NEWNYM: new circuit requested")
            else:
                logger.warning("Tor NEWNYM failed: %s", signal_resp.strip())
            return success
        except OSError as exc:
            logger.error("Tor control port error: %s", exc)
            return False

    def get_tor_session(self) -> Proxy:
        """Return a Proxy object configured for the local Tor SOCKS port."""
        url = f"socks5://{self.socks_host}:{self.socks_port}"
        return Proxy(
            url=url,
            protocol="socks5",
            host=self.socks_host,
            port=self.socks_port,
            country="tor",
        )

    # DEAD CODE: consider removal
    def verify_new_ip(self, timeout: int = 15) -> dict:
        """Make a request through Tor and verify the exit IP changed.

        Returns::

            {"ok": bool, "ip": str | None, "changed": bool}
        """
        tor_proxy = self.get_tor_session()
        try:
            result = proxy_probe("https://httpbin.org/ip", tor_proxy, timeout=timeout)
            new_ip = result.get("proxy_ip", "") or None
            changed = self._last_ip is None or (new_ip is not None and new_ip != self._last_ip)
            self._last_ip = new_ip
            return {"ok": result["ok"], "ip": new_ip, "changed": changed}
        except Exception as exc:
            return {"ok": False, "ip": None, "changed": False, "error": str(exc)}


# ── CLI Integration ──────────────────────────────────────────────────────


# DEAD CODE: consider removal
def load_default_pool() -> ProxyPool:
    """Load the default proxy pool from ``~/.reconpro/proxies.json``.

    If the file does not exist or is unreadable, returns an empty pool.
    """
    pool = ProxyPool()
    try:
        pool.load()
    except Exception as exc:
        logger.debug("Could not load default pool: %s", exc)
    return pool
