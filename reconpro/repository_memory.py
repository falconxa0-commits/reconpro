"""ReconPro Age III — Repository Memory System.

Persistent meta-knowledge store about scanned repositories and codebases.

This module is COMPLEMENTARY to ``memory.py`` and ``knowledge_graph.py``:
  - ``memory.py``            → security scan findings, credentials, attack graphs
  - ``knowledge_graph.py``  → entity-relationship graphs of network assets
  - ``history.py``          → time-series of raw scan results
  - ``repository_memory.py``→ engineering decisions, ADR references,
                             performance baselines, architecture notes,
                             tech-stack observations, and other META-KNOWLEDGE
                             about the codebase itself.

Persistence: JSON at RECONPRO_HOME/memory/repository_memory.json

Zero external dependencies.  Pure Python.  Thread-safe.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import threading
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple, Union

from .constants import MEMORY_DIR, RECONPRO_HOME

# ─── Logger ────────────────────────────────────────────────────────────

logger = logging.getLogger("reconpro.repository_memory")

# ─── Storage path ──────────────────────────────────────────────────────

REPOSITORY_MEMORY_FILE: Path = MEMORY_DIR / "repository_memory.json"

# ─── Default confidence for facts without an explicit value ────────────

DEFAULT_CONFIDENCE: float = 0.8

# ─── Expiration sentinel: None means never expires ─────────────────────

_NEVER_EXPIRES: Optional[float] = None


# ======================================================================
#  EngineeringFact — the atomic unit of repository knowledge
# ======================================================================


@dataclass
class EngineeringFact:
    """A single piece of meta-knowledge about a repository.

    Attributes:
        key:        Dot-path or slash-path identifier (e.g.
                    ``"arch/auth-decision"``, ``"perf/baseline/api-latency"``).
        value:      The stored value — any JSON-serialisable object.
        timestamp:  Unix epoch seconds when the fact was recorded.
        source:     Provenance tag (module name, agent id, "manual", etc.).
        tags:       Frozen set of classification tags for indexing.
        confidence: 0.0 – 1.0 certainty.  Facts below a query threshold are
                    excluded from results.
        expires:    Unix epoch seconds after which the fact is stale, or
                    ``None`` for permanent facts.
    """

    key: str
    value: Any
    timestamp: float = field(default_factory=time.time)
    source: str = ""
    tags: FrozenSet[str] = field(default_factory=frozenset)
    confidence: float = DEFAULT_CONFIDENCE
    expires: Optional[float] = None

    def is_expired(self, now: Optional[float] = None) -> bool:
        """Return ``True`` if this fact has passed its expiration."""
        if self.expires is None:
            return False
        check_time: float = now if now is not None else time.time()
        return check_time > self.expires

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        d: Dict[str, Any] = {
            "key": self.key,
            "value": self.value,
            "timestamp": self.timestamp,
            "source": self.source,
            "tags": sorted(self.tags),
            "confidence": self.confidence,
            "expires": self.expires,
        }
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EngineeringFact:
        """Deserialize from a dictionary (e.g. loaded from JSON)."""
        tags_raw = data.get("tags", [])
        if isinstance(tags_raw, (list, tuple, set)):
            tags = frozenset(str(t) for t in tags_raw)
        else:
            tags = frozenset()
        return cls(
            key=str(data["key"]),
            value=data["value"],
            timestamp=float(data.get("timestamp", time.time())),
            source=str(data.get("source", "")),
            tags=tags,
            confidence=float(data.get("confidence", DEFAULT_CONFIDENCE)),
            expires=data.get("expires"),  # keep None as-is
        )


# ======================================================================
#  MemoryIndex — fast multi-axes lookup
# ======================================================================


class MemoryIndex:
    """In-memory inverted index over :class:`EngineeringFact` entries.

    Maintains three axes:
      * **tag index**  — fact keys by tag
      * **time index**  — fact keys by ISO-date bucket (``YYYY-MM-DD``)
      * **source index** — fact keys by source string

    The index is rebuilt from the fact store on demand (lazy) or when
    :meth:`rebuild` is called explicitly.
    """

    def __init__(self) -> None:
        self._tag_index: Dict[str, Set[str]] = defaultdict(set)
        self._time_index: Dict[str, Set[str]] = defaultdict(set)
        self._source_index: Dict[str, Set[str]] = defaultdict(set)
        self._key_set: Set[str] = set()
        self._dirty: bool = True

    # ── Mutation ─────────────────────────────────────────────────────

    def add(self, fact: EngineeringFact) -> None:
        """Register a single fact in all index axes."""
        self._key_set.add(fact.key)
        for tag in fact.tags:
            self._tag_index[tag].add(fact.key)
        date_bucket = self._date_bucket(fact.timestamp)
        self._time_index[date_bucket].add(fact.key)
        if fact.source:
            self._source_index[fact.source].add(fact.key)

    def remove(self, fact: EngineeringFact) -> None:
        """Remove a single fact from all index axes."""
        self._key_set.discard(fact.key)
        for tag in fact.tags:
            bucket = self._tag_index.get(tag)
            if bucket is not None:
                bucket.discard(fact.key)
                if not bucket:
                    del self._tag_index[tag]
        date_bucket = self._date_bucket(fact.timestamp)
        bucket = self._time_index.get(date_bucket)
        if bucket is not None:
            bucket.discard(fact.key)
            if not bucket:
                del self._time_index[date_bucket]
        if fact.source:
            bucket = self._source_index.get(fact.source)
            if bucket is not None:
                bucket.discard(fact.key)
                if not bucket:
                    del self._source_index[fact.source]

    def clear(self) -> None:
        """Wipe all index data."""
        self._tag_index.clear()
        self._time_index.clear()
        self._source_index.clear()
        self._key_set.clear()
        self._dirty = True

    # ── Lookup ───────────────────────────────────────────────────────

    def by_tag(self, tag: str) -> Set[str]:
        """Return fact keys indexed under *tag*."""
        return set(self._tag_index.get(tag, set()))

    def by_tags(self, tags: Iterable[str]) -> Set[str]:
        """Return fact keys that have ALL of the given *tags* (intersection)."""
        tag_list = list(tags)
        if not tag_list:
            return set()
        result: Optional[Set[str]] = None
        for tag in tag_list:
            keys = self._tag_index.get(tag, set())
            if result is None:
                result = set(keys)
            else:
                result &= keys
            if not result:
                return set()
        return result or set()

    def by_time_range(self, start: float, end: float) -> Set[str]:
        """Return fact keys whose timestamp falls in [start, end]."""
        start_bucket = self._date_bucket(start)
        end_bucket = self._date_bucket(end)
        result: Set[str] = set()
        for bucket, keys in self._time_index.items():
            if start_bucket <= bucket <= end_bucket:
                result |= keys
        return result

    def by_source(self, source: str) -> Set[str]:
        """Return fact keys from a specific *source*."""
        return set(self._source_index.get(source, set()))

    def all_keys(self) -> Set[str]:
        """Return every known fact key."""
        return set(self._key_set)

    # ── Rebuild ──────────────────────────────────────────────────────

    def rebuild(self, facts: Dict[str, EngineeringFact]) -> None:
        """Rebuild the entire index from a fact dictionary."""
        self.clear()
        for fact in facts.values():
            self.add(fact)
        self._dirty = False

    @property
    def dirty(self) -> bool:
        """Whether the index is out of sync with the fact store."""
        return self._dirty

    # ── Internals ────────────────────────────────────────────────────

    @staticmethod
    def _date_bucket(timestamp: float) -> str:
        """Convert a unix timestamp to an ISO date string for bucketing."""
        try:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d")
        except (OSError, ValueError, OverflowError):
            return "1970-01-01"


# ======================================================================
#  MemoryQuery — composable query builder
# ======================================================================


class MemoryQuery:
    """Fluent query builder for :class:`RepositoryMemory` searches.

    Usage::

        results = (
            MemoryQuery()
            .with_tags({"auth", "decision"})
            .with_confidence(min_conf=0.7)
            .with_time_range(start_ts, end_ts)
            .build()
        )
        facts = memory.search(query=results)

    Queries support AND / OR / NOT combinatorics via the class methods.
    """

    def __init__(self) -> None:
        # Positive filters (all must match — AND semantics)
        self._tags: Set[str] = set()
        self._sources: Set[str] = set()
        self._key_pattern: Optional[str] = None
        self._min_confidence: float = 0.0
        self._max_confidence: float = 1.0
        self._time_start: Optional[float] = None
        self._time_end: Optional[float] = None
        self._text_query: Optional[str] = None
        self._exclude_tags: Set[str] = set()
        self._exclude_sources: Set[str] = set()
        self._exclude_keys: Set[str] = set()

    # ── Fluent setters (return self for chaining) ───────────────────

    def with_tags(self, tags: Iterable[str]) -> MemoryQuery:
        """Require ALL of *tags* to be present on matching facts."""
        self._tags.update(tags)
        return self

    def with_any_tag(self, tags: Iterable[str]) -> MemoryQuery:
        """Require at least ONE of *tags* to be present (OR within AND).

        Stored internally as a special marker; evaluated at query time.
        """
        # We use a private attribute to signal "any-tag" mode.
        # If _any_tags is set, the regular _tags AND semantics still apply,
        # but the any-tags subset is OR-checked separately.
        if not hasattr(self, "_any_tags"):
            self._any_tags: Set[str] = set()
        self._any_tags.update(tags)
        return self

    def with_sources(self, sources: Iterable[str]) -> MemoryQuery:
        """Restrict to facts from any of the given *sources*."""
        self._sources.update(sources)
        return self

    def with_key_pattern(self, pattern: str) -> MemoryQuery:
        """Shell-glob pattern matched against fact keys (fnmatch)."""
        self._key_pattern = pattern
        return self

    def with_confidence(
        self,
        min_conf: float = 0.0,
        max_conf: float = 1.0,
    ) -> MemoryQuery:
        """Filter by confidence range [min_conf, max_conf]."""
        self._min_confidence = max(0.0, min(1.0, min_conf))
        self._max_confidence = max(0.0, min(1.0, max_conf))
        return self

    def with_time_range(
        self, start: Optional[float] = None, end: Optional[float] = None
    ) -> MemoryQuery:
        """Restrict to facts recorded between *start* and *end* (unix epoch).

        Either bound may be ``None`` to leave it open.
        """
        self._time_start = start
        self._time_end = end
        return self

    def with_text(self, query_text: str) -> MemoryQuery:
        """Full-text search substring (case-insensitive) across values.

        The text is matched against the JSON-serialised representation of
        each fact's ``value`` field.
        """
        self._text_query = query_text
        return self

    def without_tags(self, tags: Iterable[str]) -> MemoryQuery:
        """Exclude facts that have ANY of the given *tags* (NOT)."""
        self._exclude_tags.update(tags)
        return self

    def without_sources(self, sources: Iterable[str]) -> MemoryQuery:
        """Exclude facts from any of the given *sources* (NOT)."""
        self._exclude_sources.update(sources)
        return self

    def without_keys(self, keys: Iterable[str]) -> MemoryQuery:
        """Exclude facts with any of the given exact *keys*."""
        self._exclude_keys.update(keys)
        return self

    # ── Combinators ──────────────────────────────────────────────────

    @classmethod
    def and_(cls, *queries: MemoryQuery) -> MemoryQuery:
        """Create a new query that ANDs the constraints of all *queries*.

        Tags and sources from all queries are unioned (since each query's
        own filters are already AND within themselves).  The tightest
        confidence/time bounds win.
        """
        combined = cls()
        for q in queries:
            combined._tags |= q._tags
            combined._sources |= q._sources
            combined._exclude_tags |= q._exclude_tags
            combined._exclude_sources |= q._exclude_sources
            combined._exclude_keys |= q._exclude_keys
            combined._min_confidence = max(combined._min_confidence, q._min_confidence)
            combined._max_confidence = min(combined._max_confidence, q._max_confidence)
            if q._time_start is not None:
                if combined._time_start is None or q._time_start > combined._time_start:
                    combined._time_start = q._time_start
            if q._time_end is not None:
                if combined._time_end is None or q._time_end < combined._time_end:
                    combined._time_end = q._time_end
            if q._key_pattern and not combined._key_pattern:
                combined._key_pattern = q._key_pattern
            if q._text_query and not combined._text_query:
                combined._text_query = q._text_query
            # any_tags
            if hasattr(q, "_any_tags") and q._any_tags:
                if not hasattr(combined, "_any_tags"):
                    combined._any_tags = set()
                combined._any_tags |= q._any_tags
        return combined

    @classmethod
    def or_(cls, *queries: MemoryQuery) -> MemoryQuery:
        """Create a new query whose filters are the LOOSEST of all *queries*.

        This is useful for building an OR-style search: the caller runs
        each sub-query independently and unions the results.  This helper
        returns a query with relaxed constraints so that a single pass
        captures the superset.
        """
        combined = cls()
        for q in queries:
            # For OR, we keep the loosest bounds
            combined._min_confidence = min(combined._min_confidence, q._min_confidence)
            combined._max_confidence = max(combined._max_confidence, q._max_confidence)
            if q._time_start is not None:
                if combined._time_start is None or q._time_start < combined._time_start:
                    combined._time_start = q._time_start
            if q._time_end is not None:
                if combined._time_end is None or q._time_end > combined._time_end:
                    combined._time_end = q._time_end
        # OR semantics: collect all include-tags as any_tags
        for q in queries:
            if q._tags:
                if not hasattr(combined, "_any_tags"):
                    combined._any_tags = set()
                combined._any_tags |= q._tags
        # OR semantics: collect all exclude-tags as intersection (keep only
        # those excluded by ALL sub-queries)
        if queries:
            first_exclude = queries[0]._exclude_tags
            for q in queries[1:]:
                first_exclude = first_exclude & q._exclude_tags
            combined._exclude_tags = first_exclude
        return combined

    @classmethod
    def not_(cls, query: MemoryQuery) -> MemoryQuery:
        """Invert a query: its positive tag/source constraints become exclusions.

        Confidence and time ranges are left open (``0.0–1.0`` and
        ``None–None``) since inverting them would be semantically
        ambiguous.
        """
        inverted = cls()
        inverted._exclude_tags = query._tags.copy()
        inverted._exclude_sources = query._sources.copy()
        if query._key_pattern:
            inverted._key_pattern = None  # can't negate a glob
        return inverted

    # ── Serialisation ────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the query to a JSON-safe dictionary."""
        d: Dict[str, Any] = {
            "tags": sorted(self._tags),
            "sources": sorted(self._sources),
            "key_pattern": self._key_pattern,
            "min_confidence": self._min_confidence,
            "max_confidence": self._max_confidence,
            "time_start": self._time_start,
            "time_end": self._time_end,
            "text_query": self._text_query,
            "exclude_tags": sorted(self._exclude_tags),
            "exclude_sources": sorted(self._exclude_sources),
            "exclude_keys": sorted(self._exclude_keys),
        }
        if hasattr(self, "_any_tags"):
            d["any_tags"] = sorted(self._any_tags)
        return d

    # ── Matching ─────────────────────────────────────────────────────

    def matches(self, fact: EngineeringFact) -> bool:
        """Return ``True`` if *fact* satisfies all query constraints."""
        # Tag AND filter
        if self._tags and not self._tags.issubset(fact.tags):
            return False

        # Any-tag OR filter
        if hasattr(self, "_any_tags") and self._any_tags:
            if not self._any_tags & fact.tags:
                return False

        # Source filter
        if self._sources and fact.source not in self._sources:
            return False

        # Key pattern
        if self._key_pattern is not None:
            if not fnmatch.fnmatch(fact.key, self._key_pattern):
                return False

        # Confidence range
        if not (self._min_confidence <= fact.confidence <= self._max_confidence):
            return False

        # Time range
        if self._time_start is not None and fact.timestamp < self._time_start:
            return False
        if self._time_end is not None and fact.timestamp > self._time_end:
            return False

        # Text query
        if self._text_query is not None:
            text_blob = json.dumps(fact.value, default=str).lower()
            if self._text_query.lower() not in text_blob:
                return False

        # Exclusion filters (NOT)
        if self._exclude_tags and self._exclude_tags & fact.tags:
            return False
        if self._exclude_sources and fact.source in self._exclude_sources:
            return False
        if self._exclude_keys and fact.key in self._exclude_keys:
            return False

        return True

    def __repr__(self) -> str:
        parts: List[str] = []
        if self._tags:
            parts.append(f"tags={sorted(self._tags)!r}")
        if hasattr(self, "_any_tags") and self._any_tags:
            parts.append(f"any_tags={sorted(self._any_tags)!r}")
        if self._sources:
            parts.append(f"sources={sorted(self._sources)!r}")
        if self._key_pattern:
            parts.append(f"key_pattern={self._key_pattern!r}")
        if self._min_confidence > 0.0 or self._max_confidence < 1.0:
            parts.append(
                f"conf=[{self._min_confidence}, {self._max_confidence}]"
            )
        if self._time_start is not None or self._time_end is not None:
            parts.append(f"time=[{self._time_start}, {self._time_end}]")
        if self._text_query:
            parts.append(f"text={self._text_query!r}")
        if self._exclude_tags:
            parts.append(f"exclude_tags={sorted(self._exclude_tags)!r}")
        return f"MemoryQuery({', '.join(parts)})"


# ======================================================================
#  Snapshot — point-in-time capture
# ======================================================================


@dataclass
class MemorySnapshot:
    """An immutable point-in-time capture of repository memory.

    Snapshots are plain dictionaries keyed by fact key, with values being
    the serialised :class:`EngineeringFact` dicts.  They can be compared
    with :meth:`RepositoryMemory.diff_snapshots`.
    """

    id: str
    created_at: float
    facts: Dict[str, Dict[str, Any]]
    fact_count: int
    total_bytes: int


def _size_of_dict(d: Dict[str, Any]) -> int:
    """Approximate byte-size of a dict when JSON-serialised."""
    return len(json.dumps(d, default=str, separators=(",", ":")))


# ======================================================================
#  RepositoryMemory — the main entry point
# ======================================================================


class RepositoryMemory:
    """Persistent repository meta-knowledge store.

    Stores engineering facts about scanned repositories and codebases:
    Architecture Decision Records, performance baselines, tech-stack
    observations, infrastructure notes, and similar meta-knowledge.

    This is COMPLEMENTARY to ``memory.UnifiedMemoryStore`` which stores
    security scan data.  Repository memory stores knowledge ABOUT the
    target codebase itself.

    Thread-safe via a reentrant lock.
    """

    def __init__(self, persist_path: Optional[Path] = None) -> None:
        self._path: Path = persist_path or REPOSITORY_MEMORY_FILE
        self._lock = threading.RLock()
        self._facts: Dict[str, EngineeringFact] = {}
        self._index = MemoryIndex()
        self._loaded: bool = False

    # ── Persistence ──────────────────────────────────────────────────

    def _ensure_dir(self) -> None:
        """Create the parent directory if it doesn't exist."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error("Cannot create directory %s: %s", self._path.parent, exc)
            raise

    def load(self) -> None:
        """Load facts from disk.  Idempotent — safe to call multiple times.

        If the file doesn't exist, starts with an empty store.
        """
        with self._lock:
            if self._loaded:
                return
            self._ensure_dir()
            if not self._path.exists():
                logger.debug("No repository memory file at %s — starting fresh.", self._path)
                self._loaded = True
                return
            try:
                raw = self._path.read_text(encoding="utf-8")
                data = json.loads(raw) if raw.strip() else {}
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning(
                    "Corrupt repository memory file %s: %s — starting fresh.",
                    self._path, exc,
                )
                data = {}

            count = 0
            for key, fact_dict in data.items():
                if not isinstance(fact_dict, dict) or "key" not in fact_dict:
                    logger.debug("Skipping invalid fact entry: %s", key)
                    continue
                try:
                    fact = EngineeringFact.from_dict(fact_dict)
                    if fact.is_expired():
                        logger.debug("Skipping expired fact: %s", fact.key)
                        continue
                    self._facts[fact.key] = fact
                    count += 1
                except (KeyError, TypeError, ValueError) as exc:
                    logger.debug("Skipping malformed fact %s: %s", key, exc)

            self._index.rebuild(self._facts)
            self._loaded = True
            logger.info(
                "Loaded %d repository facts from %s", count, self._path
            )

    def save(self) -> None:
        """Flush all in-memory facts to disk.

        Expired facts are pruned before writing.
        """
        with self._lock:
            self._ensure_dir()
            self._prune_expired()
            data: Dict[str, Dict[str, Any]] = {}
            for key, fact in self._facts.items():
                data[key] = fact.to_dict()
            try:
                tmp_path = self._path.with_suffix(".tmp")
                tmp_path.write_text(
                    json.dumps(data, indent=2, default=str, ensure_ascii=False),
                    encoding="utf-8",
                )
                # Atomic rename
                tmp_path.replace(self._path)
                logger.debug(
                    "Saved %d repository facts to %s", len(data), self._path
                )
            except OSError as exc:
                logger.error("Failed to save repository memory: %s", exc)
                raise

    def _ensure_loaded(self) -> None:
        """Lazy-load if not already loaded."""
        if not self._loaded:
            self.load()

    def _prune_expired(self) -> int:
        """Remove expired facts.  Returns count of pruned entries."""
        now = time.time()
        expired_keys = [
            k for k, f in self._facts.items() if f.is_expired(now)
        ]
        for key in expired_keys:
            self._index.remove(self._facts[key])
            del self._facts[key]
        if expired_keys:
            logger.debug("Pruned %d expired facts.", len(expired_keys))
        return len(expired_keys)

    # ── Core CRUD ────────────────────────────────────────────────────

    def remember(
        self,
        key: str,
        value: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EngineeringFact:
        """Store a fact about the repository.

        Args:
            key:      Unique identifier (dot/slash path recommended).
            value:    Any JSON-serialisable value.
            metadata: Optional dict with keys:
                      ``source`` (str), ``tags`` (list[str]),
                      ``confidence`` (float 0–1),
                      ``expires`` (float unix timestamp or None),
                      ``timestamp`` (float unix timestamp).

        Returns:
            The created :class:`EngineeringFact`.
        """
        with self._lock:
            self._ensure_loaded()
            meta = metadata or {}

            # If the key already exists, remove old index entries
            if key in self._facts:
                self._index.remove(self._facts[key])

            tags_raw = meta.get("tags", [])
            if isinstance(tags_raw, str):
                tags_raw = [tags_raw]
            tags = frozenset(str(t) for t in tags_raw)

            fact = EngineeringFact(
                key=key,
                value=value,
                timestamp=float(meta.get("timestamp", time.time())),
                source=str(meta.get("source", "")),
                tags=tags,
                confidence=float(meta.get("confidence", DEFAULT_CONFIDENCE)),
                expires=meta.get("expires"),
            )

            self._facts[key] = fact
            self._index.add(fact)
            logger.debug("Remembered fact: %s", key)
            return fact

    def recall(self, key: str) -> Optional[EngineeringFact]:
        """Retrieve a single fact by exact key.

        Returns ``None`` if the key doesn't exist or the fact is expired.
        """
        with self._lock:
            self._ensure_loaded()
            fact = self._facts.get(key)
            if fact is None:
                return None
            if fact.is_expired():
                self._index.remove(fact)
                del self._facts[key]
                return None
            return fact

    def recall_pattern(self, pattern_glob: str) -> List[EngineeringFact]:
        """Find facts whose keys match a shell glob *pattern_glob*.

        Uses ``fnmatch`` for matching.  Returns facts sorted by key.
        Expired facts are excluded.
        """
        with self._lock:
            self._ensure_loaded()
            now = time.time()
            results: List[EngineeringFact] = []
            for key, fact in self._facts.items():
                if fnmatch.fnmatch(key, pattern_glob) and not fact.is_expired(now):
                    results.append(fact)
            results.sort(key=lambda f: f.key)
            return results

    def forget(self, key: str) -> bool:
        """Remove a fact by exact key.

        Returns ``True`` if the fact existed and was removed,
        ``False`` if it wasn't found.
        """
        with self._lock:
            self._ensure_loaded()
            fact = self._facts.pop(key, None)
            if fact is None:
                return False
            self._index.remove(fact)
            logger.debug("Forgot fact: %s", key)
            return True

    # ── Search ───────────────────────────────────────────────────────

    def search(
        self,
        query_text: Optional[str] = None,
        query: Optional[MemoryQuery] = None,
        limit: int = 100,
    ) -> List[EngineeringFact]:
        """Search facts.

        Args:
            query_text: Free-text substring searched across fact keys and
                        JSON-serialised values (case-insensitive).  Used when
                        *query* is ``None``.
            query:      A :class:`MemoryQuery` object for structured search.
            limit:      Maximum results to return.

        Returns:
            Matching facts sorted by confidence descending, then timestamp
            descending (most recent first).
        """
        with self._lock:
            self._ensure_loaded()
            now = time.time()

            # Build a MemoryQuery from query_text if no query object given
            if query is None and query_text is not None:
                query = MemoryQuery().with_text(query_text)

            if query is None:
                # No filters — return all non-expired facts
                results = [
                    f for f in self._facts.values() if not f.is_expired(now)
                ]
            else:
                results = [
                    f
                    for f in self._facts.values()
                    if not f.is_expired(now) and query.matches(f)
                ]

            # Sort: confidence desc, then timestamp desc
            results.sort(key=lambda f: (f.confidence, f.timestamp), reverse=True)
            return results[:limit]

    # ── Snapshots ────────────────────────────────────────────────────

    def snapshot(self, label: str = "") -> MemorySnapshot:
        """Create a point-in-time snapshot of all current (non-expired) facts.

        Args:
            label: Optional human-readable label stored in the snapshot id.

        Returns:
            A :class:`MemorySnapshot` containing copies of all facts.
        """
        with self._lock:
            self._ensure_loaded()
            now = time.time()
            facts_copy: Dict[str, Dict[str, Any]] = {}
            for key, fact in self._facts.items():
                if not fact.is_expired(now):
                    facts_copy[key] = fact.to_dict()

            snap_id = f"snap_{int(now * 1000)}"
            if label:
                snap_id = f"{snap_id}_{label}"

            total_bytes = _size_of_dict(facts_copy)
            return MemorySnapshot(
                id=snap_id,
                created_at=now,
                facts=facts_copy,
                fact_count=len(facts_copy),
                total_bytes=total_bytes,
            )

    @staticmethod
    def diff_snapshots(
        snap_a: MemorySnapshot, snap_b: MemorySnapshot,
    ) -> Dict[str, Any]:
        """Compare two snapshots and return a structured diff.

        Args:
            snap_a: The earlier snapshot.
            snap_b: The later snapshot.

        Returns:
            A dict with keys:
              ``added``    — keys present in B but not A
              ``removed``  — keys present in A but not B
              ``modified`` — keys present in both but with different values
              ``unchanged``— keys present in both with identical values
              ``stats``    — summary counts
        """
        keys_a = set(snap_a.facts.keys())
        keys_b = set(snap_b.facts.keys())

        added = sorted(keys_b - keys_a)
        removed = sorted(keys_a - keys_b)
        common = keys_a & keys_b

        modified: List[str] = []
        unchanged: List[str] = []
        for key in sorted(common):
            val_a = json.dumps(
                snap_a.facts[key]["value"], sort_keys=True, default=str
            )
            val_b = json.dumps(
                snap_b.facts[key]["value"], sort_keys=True, default=str
            )
            if val_a != val_b:
                modified.append(key)
            else:
                unchanged.append(key)

        return {
            "snapshot_a": {
                "id": snap_a.id,
                "created_at": snap_a.created_at,
                "fact_count": snap_a.fact_count,
            },
            "snapshot_b": {
                "id": snap_b.id,
                "created_at": snap_b.created_at,
                "fact_count": snap_b.fact_count,
            },
            "added": added,
            "removed": removed,
            "modified": modified,
            "unchanged": unchanged,
            "stats": {
                "added_count": len(added),
                "removed_count": len(removed),
                "modified_count": len(modified),
                "unchanged_count": len(unchanged),
                "net_change": len(added) - len(removed),
            },
        }

    # ── Statistics ───────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics about the memory store.

        Includes:
          - ``total_facts`` — count of non-expired facts
          - ``expired_facts`` — count of expired (but not yet pruned) facts
          - ``total_bytes`` — approximate JSON size of all facts
          - ``tag_distribution`` — tag → count mapping
          - ``source_distribution`` — source → count mapping
          - ``age_distribution`` — bucketed age ranges (in seconds)
          - ``confidence_stats`` — min, max, average confidence
          - ``oldest_fact`` — timestamp of the oldest fact
          - ``newest_fact`` — timestamp of the newest fact
        """
        with self._lock:
            self._ensure_loaded()
            now = time.time()

            active_facts: List[EngineeringFact] = []
            expired_count = 0
            tag_dist: Dict[str, int] = defaultdict(int)
            source_dist: Dict[str, int] = defaultdict(int)

            for fact in self._facts.values():
                if fact.is_expired(now):
                    expired_count += 1
                    continue
                active_facts.append(fact)
                for tag in fact.tags:
                    tag_dist[tag] += 1
                if fact.source:
                    source_dist[fact.source] += 1

            # Age distribution buckets (seconds)
            age_buckets: Dict[str, int] = {
                "<1h": 0,
                "1h-24h": 0,
                "1d-7d": 0,
                "7d-30d": 0,
                ">30d": 0,
            }
            for fact in active_facts:
                age = now - fact.timestamp
                if age < 3600:
                    age_buckets["<1h"] += 1
                elif age < 86400:
                    age_buckets["1h-24h"] += 1
                elif age < 604800:
                    age_buckets["1d-7d"] += 1
                elif age < 2592000:
                    age_buckets["7d-30d"] += 1
                else:
                    age_buckets[">30d"] += 1

            # Confidence stats
            if active_facts:
                confs = [f.confidence for f in active_facts]
                conf_min = min(confs)
                conf_max = max(confs)
                conf_avg = sum(confs) / len(confs)
            else:
                conf_min = 0.0
                conf_max = 0.0
                conf_avg = 0.0

            # Oldest / newest
            oldest: Optional[float] = None
            newest: Optional[float] = None
            for fact in active_facts:
                if oldest is None or fact.timestamp < oldest:
                    oldest = fact.timestamp
                if newest is None or fact.timestamp > newest:
                    newest = fact.timestamp

            # Total bytes
            all_data = {k: f.to_dict() for k, f in self._facts.items()}
            total_bytes = _size_of_dict(all_data)

            return {
                "total_facts": len(active_facts),
                "expired_facts": expired_count,
                "total_bytes": total_bytes,
                "tag_distribution": dict(sorted(tag_dist.items())),
                "source_distribution": dict(sorted(source_dist.items())),
                "age_distribution": age_buckets,
                "confidence_stats": {
                    "min": round(conf_min, 3),
                    "max": round(conf_max, 3),
                    "avg": round(conf_avg, 3),
                },
                "oldest_fact": oldest,
                "newest_fact": newest,
            }

    # ── Bulk operations ──────────────────────────────────────────────

    def recall_by_tag(self, tag: str) -> List[EngineeringFact]:
        """Retrieve all facts tagged with *tag*.

        Uses the index for O(1) tag lookup rather than scanning all facts.
        """
        with self._lock:
            self._ensure_loaded()
            now = time.time()
            keys = self._index.by_tag(tag)
            results = [
                self._facts[k]
                for k in keys
                if k in self._facts and not self._facts[k].is_expired(now)
            ]
            results.sort(key=lambda f: f.timestamp, reverse=True)
            return results

    def recall_by_source(self, source: str) -> List[EngineeringFact]:
        """Retrieve all facts from a specific *source*.

        Uses the index for fast source-based lookup.
        """
        with self._lock:
            self._ensure_loaded()
            now = time.time()
            keys = self._index.by_source(source)
            results = [
                self._facts[k]
                for k in keys
                if k in self._facts and not self._facts[k].is_expired(now)
            ]
            results.sort(key=lambda f: f.timestamp, reverse=True)
            return results

    def recall_by_time_range(
        self, start: float, end: float
    ) -> List[EngineeringFact]:
        """Retrieve all facts recorded between *start* and *end* (unix epoch).
        """
        with self._lock:
            self._ensure_loaded()
            now = time.time()
            keys = self._index.by_time_range(start, end)
            results = [
                self._facts[k]
                for k in keys
                if k in self._facts
                and not self._facts[k].is_expired(now)
                and start <= self._facts[k].timestamp <= end
            ]
            results.sort(key=lambda f: f.timestamp, reverse=True)
            return results

    def clear(self) -> int:
        """Remove all facts.  Returns the count of removed entries.

        Does NOT affect the on-disk file until :meth:`save` is called.
        """
        with self._lock:
            self._ensure_loaded()
            count = len(self._facts)
            self._facts.clear()
            self._index.clear()
            logger.info("Cleared %d repository facts.", count)
            return count

    def all_keys(self) -> List[str]:
        """Return all non-expired fact keys, sorted."""
        with self._lock:
            self._ensure_loaded()
            now = time.time()
            return sorted(
                k for k, f in self._facts.items() if not f.is_expired(now)
            )

    def count(self) -> int:
        """Return count of non-expired facts."""
        with self._lock:
            self._ensure_loaded()
            now = time.time()
            return sum(1 for f in self._facts.values() if not f.is_expired(now))

    def __len__(self) -> int:
        return self.count()

    def __contains__(self, key: str) -> bool:
        with self._lock:
            self._ensure_loaded()
            fact = self._facts.get(key)
            if fact is None:
                return False
            if fact.is_expired():
                self._index.remove(fact)
                del self._facts[key]
                return False
            return True
