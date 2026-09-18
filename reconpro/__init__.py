"""ReconPro Enterprise v11 — The Security Reconnaissance Platform.

Twenty-Seven Blades. One Target. One Verdict.
Pure Python. Enterprise-grade.

Remote Modules:
    recon      13-category surface reconnaissance
    auth       15 auth bypass techniques
    chain      SSRF + redirect chain hunting
    bot        C2 / bot infrastructure detection
    gorgon     15-stage AI red team
    oblivion   23-stage analytical dissolution (DREAD)
    vibesec    AI/vibe-coding vulnerability benchmark
    nhi        Non-Human Identity & blast-radius mapping
    pegasus    Pegasus spyware/surveillance detection
    cloud_recon Cloud infrastructure reconnaissance
    team       Team collaboration & shared scans

Advanced Modules:
    quantum_fingerprint  OS/kernel fingerprinting via HTTP timing
    dark_web_monitor     Credential leak & exposure scanner
    info_ops             Information operations & deception analysis
    steganography_detector Hidden data & covert channel detection
    covert_channel       Covert channel detection & simulation
    zero_day_hunter      Anomaly-based zero-day pattern detection
    infrastructure_ghost Complete infrastructure ghosting
    signal_intelligence  SIGINT for HTTP (beaconing, C2)
    nation_state_attributor Nation-state attack attribution engine
    weaponized_report    Tracking & beacon detection in documents
    honeypot_dance       Honeypot detection & effectiveness scoring
    dead_drop            Cryptographic dead drop detection

Local Modules:
    host       Full laptop/machine security audit
    dev        Developer security scan (secrets, deps, git, docker)
    doctor     Security health check with fix commands

Powers:
    chat       Interactive REPL — talk to ReconPro naturally
    nexus      Visual terminal dashboard with mouse + keyboard
    blitz      Parallel multi-target scanning
    agent      Autonomous goal-driven scanning
    subdomains Subdomain discovery (CT logs + DNS)
    schedule   Cron-like recurring scans
    serve      REST API server
    report     HTML report generation
    history    Scan history with diff/comparison
    plugin     Custom module system
    screenshot Browser screenshots (Playwright)
    swarm      Multi-agent attack swarm
    adversarial Self-play hacker vs coder

Intelligence Systems:
    ai_analyst         AI Security Analyst — classification, correlation, attack paths
    attack_graph        Attack Graph Engine — graph-based attack chain analysis
    threat_intel        Threat Intelligence Center — CVE/CWE/CAPEC/MITRE enrichment

Engineering Systems (Age III):
    auto_engineering        Automated engineering pipeline — health, drift, quality gates
    repository_memory       Persistent engineering knowledge store
    digital_twin            Virtual model of the ReconPro runtime
    repository_learning     Pattern extraction and prediction from repository behavior
    engineering_recommendations Rule-based engineering recommendation engine
    regression_intelligence  Intelligent regression detection and management
    auto_validation         Automated validation pipeline (syntax, imports, security, perf)
    benchmark_automation     Continuous benchmark automation with regression detection
    auto_fix                Auto fix proposal engine with AST-based transforms
    prompt_defense          Prompt injection defense for AI/chat inputs
    security_hardening      Security policy engine, plugin sandbox, tamper-evident logs
    quality_intelligence    Multi-dimensional code quality analysis (AST-based)

Usage:
    reconpro example.com                    # Remote scan
    reconpro chat                          # Talk to it
    reconpro nexus                         # Visual dashboard
    reconpro audit                         # Scan your laptop
    reconpro blitz t1.com t2.com t3.com    # Parallel scan
    reconpro agent scan everything          # Autonomous
    reconpro subdomains example.com         # Discover subs
    reconpro serve                          # API server
    reconpro engineering                    # Full engineering pipeline
    reconpro validate                      # Run validation pipeline
    reconpro benchmark                      # Run benchmarks
"""

__version__ = "11.2.0"
__all__ = ["scan", "ReconProResult", "audit_scan", "__version__"]

# ── Lazy imports (PEP 562) ────────────────────────────────────────────────
# `import reconpro` must stay cheap (<30 ms): the engine pulls the full
# module registry (~300 ms) and is only needed when an actual scan runs.
# Attribute access (`reconpro.scan`, `from reconpro import scan`) resolves
# on demand below.
_LAZY_ATTRS = {
    "scan": (".engine", "scan"),
    "audit_scan": (".engine", "audit_scan"),
    "ReconProResult": (".scanner", "ReconProResult"),
}


def __getattr__(name: str):
    spec = _LAZY_ATTRS.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib
    module = importlib.import_module(spec[0], package=__name__)
    value = getattr(module, spec[1])
    globals()[name] = value  # cache: subsequent lookups are direct
    return value


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_LAZY_ATTRS))
