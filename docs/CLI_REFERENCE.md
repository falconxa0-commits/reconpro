# CLI Reference — reconpro 11.1.0

Every subcommand of `reconpro` with its real usage line, options and
examples. All usage lines and options tables below are captured from the
actual `reconpro <cmd> --help` output of this repository (81 subcommands
were run and captured; none is invented).

Commands that reach out to the network are marked **(network)** in the
example. Everything else runs locally.

## Top level

```
usage: reconpro [-h] [--version] {scan,vibesec,audit,dev,ports,secrets,list,nexus,chat,tui,blitz,agent,subdomains,schedule,serve,report,dashboard,history,diff,screenshot,open,plugin,doctor,tutorial,wizard,playground,suggest,swarm,adversarial,ast,cve,graph,iac,container,cloud-recon,defense,fuzzer,profile,compliance,delta,benchmark,graph-visual,netmap,passive,export,zai,wishes,geoip,threat-feeds,ai-redteam,supply-chain,cross-validate,quantum-fingerprint,dark-web,info-ops,steg,covert,zero-day,ghost,sigint,attributor,weaponized-report,honeypot,rate,dead-drop,info,engineering,validate,benchmark-engineering,recommendations,memory,digital-twin,auto-fix,regression,health,deps,palette,theme,workspace,notifications,copilot} ...
```

| Option | Description |
|---|---|
| `-h, --help` | show this help message and exit |
| `--version, -v` | show program's version number and exit |

Shorthand: `reconpro example.com` (a bare first argument that is not a
known subcommand) is interpreted as `reconpro scan example.com` — i.e.
it starts a **network scan**.

## Exit codes

| Exit code | Meaning | Verified example |
|---|---|---|
| `0` | success | `reconpro --version`, `reconpro tutorial --list`, `reconpro suggest --json`, `reconpro plugin list`, `reconpro doctor --json` |
| `1` | runtime error (unknown subcommand after the banner, plugin action failure, `plugin verify` FAIL, `tutorial --step` out of range) | `reconpro nosuchcmd` → prints banner then error, exit 1; `reconpro plugin verify <bad>` → exit 1 |
| `2` | usage error — argparse strict mode: unknown/missing arguments always exit 2 | `reconpro --bogus-flag` → exit 2; `reconpro plugin` (no action) → exit 2; `reconpro history --json` → exit 2 (there is no `--json` flag on `history`) |

The CLI is **strict**: unrecognized arguments are never silently ignored
(`cli.py` calls `parser.parse_args()` with no `parse_known_args`
fallback), so typos fail loudly with exit 2. This makes the CLI safe to
script in CI.

## JSON output convention

Commands with a `--json` flag print machine-readable JSON on **stdout**;
human-readable (Rich table) output goes to **stderr**. `--version` goes
to stdout. Example: `reconpro doctor --json > out.json 2> /dev/null`
gives clean JSON even while the banner and progress spinner render on
stderr.

Caveat (verified): `reconpro history` has **no** `--json` flag; its human
table is printed to stderr and `reconpro history --json` exits 2.

---
## Fast-path commands

### `reconpro list`

List the 28-module catalog (28 remote/advanced + local modules).

```
reconpro list [-h] [--local] [--all]
```

**Options:**

| Option | Description |
|---|---|
| `--local` | Include local modules |
| `--all` | Show all modules (remote + local + advanced) |

**Examples:**

```bash
reconpro list
reconpro list --all
```

### `reconpro tutorial`

Interactive guided 8-step tutorial.

```
reconpro tutorial [-h] [--step STEP] [--list]
```

**Options:**

| Option | Description |
|---|---|
| `--step STEP` | Jump to a specific step (1-8) |
| `--list` | List tutorial steps |

**Examples:**

```bash
reconpro tutorial
reconpro tutorial --list
reconpro tutorial --step 3
```

### `reconpro wizard`

Interactive scan wizard (guided Q&A).

```
reconpro wizard [-h] [--non-interactive]
```

**Options:**

| Option | Description |
|---|---|
| `--non-interactive` | Print the recommended plan without asking |

**Examples:**

```bash
reconpro wizard
reconpro wizard --non-interactive
```

### `reconpro playground`

Sandboxed plugin playground — runs a plugin .py (or built-in template) inside the sandbox without installing it.

```
reconpro playground [-h] [--target TARGET] [file]
```

**Arguments:**

| Argument | Description |
|---|---|
| `file` | Plugin .py file to experiment with |

**Options:**

| Option | Description |
|---|---|
| `--target TARGET, -t TARGET` | Target for the plugin run |

**Examples:**

```bash
reconpro playground
reconpro playground my-plugin.py --target example.com  # (network only if the plugin needs it)
```

### `reconpro suggest`

Suggest next commands based on current state (history, plugins, doctor).

```
reconpro suggest [-h] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--json` | Output JSON (stdout); human output goes to stderr |

**Examples:**

```bash
reconpro suggest
reconpro suggest --json
```

### `reconpro plugin`

Plugin management (sandboxed SDK). See [PLUGINS.md](PLUGINS.md) for the full lifecycle.

```
reconpro plugin [-h] [--allow-unsigned] [--json] {list,create,create-sdk,run,install,verify,upgrade,remove,sign,keys} [name] [target]
```

**Arguments:**

| Argument | Description |
|---|---|
| `{list,create,create-sdk,run,install,verify,upgrade,remove,sign,keys}` | Action |
| `name` | Plugin id / path / name (action-dependent) |
| `target` | Target (run action) |

**Options:**

| Option | Description |
|---|---|
| `--allow-unsigned` | install: accept unsigned plugins (recorded untrusted) |
| `--json` | Machine-readable output |

**Examples:**

```bash
reconpro plugin list
reconpro plugin keys
reconpro plugin run my-plugin example.com   # (network)
```

### `reconpro doctor`

Local health check with fix commands.

```
reconpro doctor [-h] [--repair] [--json] [-o OUTPUT_FILE]
```

**Options:**

| Option | Description |
|---|---|
| `--repair` | Automatically apply safe fixes (cache clear, stale |
| `--json` | Output JSON (stdout); human output goes to stderr |

**Examples:**

```bash
reconpro doctor
reconpro doctor --json
reconpro doctor --repair
```


## Core scanning

### `reconpro scan`

Full remote scan of a target (network).

```
reconpro scan [-h] [--modules MODULES] [--all] [--json] [-o OUTPUT_FILE] [--timeout TIMEOUT] [--insecure] [--rate-limit RATE_LIMIT] [--engineering] [--intelligence] [--no-intelligence] [--quality] [--defense] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target domain or URL |

**Options:**

| Option | Description |
|---|---|
| `--modules MODULES, -m MODULES` | Comma-separated module list (argparse shows no description) |
| `--all, -a` | Run all modules |
| `--json` | Output JSON (stdout); human output goes to stderr |
| `--timeout TIMEOUT, -t TIMEOUT` | Scan timeout in seconds |
| `--insecure, -k` | Skip TLS verification (TLS is verified by default; this is the single audited opt-out) |
| `--rate-limit RATE_LIMIT` | Requests per second limit |
| `--engineering` | Run engineering pipeline after scan |
| `--intelligence` | Enable intelligence pipeline (default: on) |
| `--no-intelligence` | Disable intelligence pipeline |
| `--quality` | Enable quality intelligence scoring |
| `--defense` | Enable prompt defense validation on AI inputs |

**Examples:**

```bash
reconpro scan example.com  # (network)
reconpro scan example.com --modules recon,auth --json -o out.json --timeout 60  # (network)
```

### `reconpro vibesec`

Quick VibeSec AI/vibe-coding benchmark (network).

```
reconpro vibesec [-h] [--json] [-o OUTPUT_FILE] [--timeout TIMEOUT] [--insecure] [--rate-limit RATE_LIMIT] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target domain or URL |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output JSON (stdout); human output goes to stderr |
| `--timeout TIMEOUT, -t TIMEOUT` | Scan timeout in seconds |
| `--insecure, -k` | Skip TLS verification (TLS is verified by default; this is the single audited opt-out) |
| `--rate-limit RATE_LIMIT` | Requests per second limit |

**Examples:**

```bash
reconpro vibesec example.com  # (network)
reconpro vibesec example.com --json  # (network)
```

### `reconpro audit`

Full local machine audit (ports, firewall, SSH, Docker, env, files) — no target argument needed.

```
reconpro audit [-h] [--modules MODULES] [--json] [-o OUTPUT_FILE] [--engineering] [--intelligence] [--no-intelligence] [--quality] [--defense]
```

**Options:**

| Option | Description |
|---|---|
| `--modules MODULES, -m MODULES` | Comma-separated module list (argparse shows no description) |
| `--json` | Output JSON (stdout); human output goes to stderr |
| `--engineering` | Run engineering pipeline after audit |
| `--intelligence` | Enable intelligence pipeline (default: on) |
| `--no-intelligence` | Disable intelligence pipeline |
| `--quality` | Enable quality intelligence scoring |
| `--defense` | Enable prompt defense validation on AI inputs |

**Examples:**

```bash
reconpro audit
reconpro audit --json -o audit.json
```

### `reconpro dev`

Developer project scan (secrets, deps, git, docker).

```
reconpro dev [-h] [--json] [-o OUTPUT_FILE] [path]
```

**Arguments:**

| Argument | Description |
|---|---|
| `path` | Directory (or file) to scan — not documented in `--help` |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output JSON (stdout); human output goes to stderr |

**Examples:**

```bash
reconpro dev /path/to/project
reconpro dev /path/to/project --json
```

### `reconpro ports`

Show open ports and risky services (local).

```
reconpro ports [-h] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--json` | Output JSON (stdout); human output goes to stderr |

**Examples:**

```bash
reconpro ports
reconpro ports --json
```

### `reconpro secrets`

Find secrets in env vars and a codebase.

```
reconpro secrets [-h] [--json] [path]
```

**Arguments:**

| Argument | Description |
|---|---|
| `path` | Directory (or file) to scan — not documented in `--help` |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output JSON (stdout); human output goes to stderr |

**Examples:**

```bash
reconpro secrets
reconpro secrets /path/to/code --json
```

### `reconpro blitz`

Parallel multi-target scan (network).

```
reconpro blitz [-h] [--workers WORKERS] [--modules MODULES] targets [targets ...]
```

**Arguments:**

| Argument | Description |
|---|---|
| `targets` | Target domains/URLs |

**Options:**

| Option | Description |
|---|---|
| `--workers WORKERS, -w WORKERS` | Parallel workers |
| `--modules MODULES, -m MODULES` | Comma-separated module list (argparse shows no description) |

**Examples:**

```bash
reconpro blitz t1.com t2.com  # (network)
reconpro blitz t1.com t2.com --workers 4  # (network)
```

### `reconpro subdomains`

Discover subdomains (network).

```
reconpro subdomains [-h] [--json] domain
```

**Arguments:**

| Argument | Description |
|---|---|
| `domain` | Domain to enumerate |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output JSON (stdout); human output goes to stderr |

**Examples:**

```bash
reconpro subdomains example.com  # (network)
reconpro subdomains example.com --json  # (network)
```

### `reconpro profile`

Target fingerprinting + auto scan plan (network).

```
reconpro profile [-h] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target domain or URL |

**Examples:**

```bash
reconpro profile example.com  # (network)
```

### `reconpro benchmark`

Score tracking + competitive leaderboard.

```
reconpro benchmark [-h] [--days DAYS] [--leaderboard] [targets ...]
```

**Arguments:**

| Argument | Description |
|---|---|
| `targets` | Targets to benchmark |

**Options:**

| Option | Description |
|---|---|
| `--days DAYS, -d DAYS` | Look-back window in days |
| `--leaderboard` | Show leaderboard |

**Examples:**

```bash
reconpro benchmark
reconpro benchmark --leaderboard
reconpro benchmark example.com --days 30  # (network)
```


## Interactive, agents & TUI

### `reconpro nexus`

Launch NEXUS — agent TUI (mouse + keyboard + split-screen).

```
reconpro nexus [-h]
```

**Examples:**

```bash
reconpro nexus
```

### `reconpro chat`

Interactive chat mode — talk to ReconPro.

```
reconpro chat [-h]
```

**Examples:**

```bash
reconpro chat
```

### `reconpro tui`

Visual terminal dashboard.

```
reconpro tui [-h]
```

**Examples:**

```bash
reconpro tui
```

### `reconpro palette`

Interactive command palette (Ctrl+K).

```
reconpro palette [-h] [--theme THEME]
```

**Options:**

| Option | Description |
|---|---|
| `--theme THEME` | Override theme |

**Examples:**

```bash
reconpro palette
reconpro palette --theme dark
```

### `reconpro theme`

Manage terminal themes.

```
reconpro theme [-h] [{list,set,current}] [name]
```

**Arguments:**

| Argument | Description |
|---|---|
| `{list,set,current}` | list\|set\|current |
| `name` | Theme name to set |

**Examples:**

```bash
reconpro theme list
reconpro theme set <name>
```

### `reconpro copilot`

AI Copilot — explain, summarize, remediate, compare.

```
reconpro copilot [-h] [--finding FINDING] [--json] [{chat,explain,summarize,remediate,compare}] [args ...]
```

**Arguments:**

| Argument | Description |
|---|---|
| `{chat,explain,summarize,remediate,compare}` | Action |
| `args` | Arguments (finding title, question, etc.) |

**Options:**

| Option | Description |
|---|---|
| `--finding FINDING` | Finding title to explain |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro copilot
reconpro copilot explain "Hardcoded password in sample.py"
reconpro copilot --finding "Hardcoded password" explain
```

### `reconpro zai`

z.ai live stream AI analysis — zero config, no API keys needed.

```
reconpro zai [-h] [--stream] [--no-stream] [--chat CHAT] [--health] [--model MODEL] [target]
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target to scan and analyze (optional: uses last scan if |

**Options:**

| Option | Description |
|---|---|
| `--stream` | Stream AI analysis in real-time (default) |
| `--no-stream` | Return complete analysis at once |
| `--chat CHAT` | Free-form chat message (skips scan) |
| `--health` | Health check: verify z.ai connectivity |
| `--model MODEL` | Model name (default: glm-4-flash) |

**Examples:**

```bash
reconpro zai  # analyzes last scan
reconpro zai example.com  # (network)
reconpro zai --health
reconpro zai --chat "what should I fix first?"
```

### `reconpro agent`

Autonomous agent — give it a natural-language goal.

```
reconpro agent [-h] goal
```

**Arguments:**

| Argument | Description |
|---|---|
| `goal` | Natural language goal (e.g. 'fully scan example.com and find |

**Examples:**

```bash
reconpro agent "fully recon example.com"  # (network)
```

### `reconpro swarm`

Swarm attack: SCOUT→HACKER→CODER→GUARDIAN (network).

```
reconpro swarm [-h] [--mode {full,recon,attack,fix,verify}] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target domain or URL |

**Options:**

| Option | Description |
|---|---|
| `--mode {full,recon,attack,fix,verify}, -m {…}` | Swarm mode |

**Examples:**

```bash
reconpro swarm example.com  # (network)
reconpro swarm example.com --mode attack  # (network)
```

### `reconpro adversarial`

Adversarial self-play: hacker vs coder loop (network).

```
reconpro adversarial [-h] [--rounds ROUNDS] [--modules MODULES] [--local] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target domain or URL |

**Options:**

| Option | Description |
|---|---|
| `--rounds ROUNDS, -r ROUNDS` | Number of self-play rounds |
| `--modules MODULES, -m MODULES` | Comma-separated module list (argparse shows no description) |
| `--local` | Target is local machine |

**Examples:**

```bash
reconpro adversarial example.com  # (network)
reconpro adversarial example.com --rounds 2 --local  # local mode, no network
```

### `reconpro wishes`

Execute 22-Wish orchestration ritual against a target (network).

```
reconpro wishes [-h] [--modules MODULES] [--timeout TIMEOUT] [--insecure] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target domain or URL |

**Options:**

| Option | Description |
|---|---|
| `--modules MODULES, -m MODULES` | Comma-separated modules to include |
| `--timeout TIMEOUT` | Timeout (seconds) |
| `--insecure, -k` | Skip TLS verification |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro wishes example.com  # (network)
reconpro wishes example.com --modules recon,auth  # (network)
```


## Reporting, export & history

### `reconpro report`

Generate production report (markdown/JSON/HTML) from the last scan.

```
reconpro report [-h] [-i INPUT] [--json] [--html] [--markdown] [-o OUTPUT_FILE]
```

**Options:**

| Option | Description |
|---|---|
| `--json` | Output JSON report |
| `--html` | Output HTML report (default if omitted without --json) |
| `--markdown` | Output Markdown report (default text format) |

**Examples:**

```bash
reconpro report
reconpro report --markdown -o report.md
reconpro report --html -o report.html
```

### `reconpro export`

Export last scan to SARIF/MD/JSON/HTML (format from extension).

```
reconpro export [-h] [output]
```

**Arguments:**

| Argument | Description |
|---|---|
| `output` | Output path (format auto-detected from extension) |

**Examples:**

```bash
reconpro export report.sarif
reconpro export report.md
reconpro export report.json
```

### `reconpro dashboard`

Unified status dashboard.

```
reconpro dashboard [-h] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro dashboard
reconpro dashboard --json
```

### `reconpro history`

View scan history (human table; there is no --json flag — see exit codes).

```
reconpro history [-h] [--limit LIMIT] [--clear] [target]
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target (optional filter) |

**Options:**

| Option | Description |
|---|---|
| `--limit LIMIT, -n LIMIT` | Max rows to show |
| `--clear` | Delete all history |

**Examples:**

```bash
reconpro history
reconpro history --limit 5
reconpro history --clear
```

### `reconpro diff`

Compare two scan results.

```
reconpro diff [-h] [a] [b]
```

**Arguments:**

| Argument | Description |
|---|---|
| `a` | First scan file or 'last' |
| `b` | Second scan file or 'last-2' |

**Examples:**

```bash
reconpro diff last last-2
```

### `reconpro compliance`

Compliance mapping (SOC2/ISO/PCI/HIPAA/GDPR/CIS).

```
reconpro compliance [-h] [--frameworks FRAMEWORKS] [-i INPUT]
```

**Options:**

| Option | Description |
|---|---|
| `--frameworks FRAMEWORKS, -f FRAMEWORKS` | Comma-separated frameworks |

**Examples:**

```bash
reconpro compliance
reconpro compliance --frameworks soc2,iso -i scan.json
```

### `reconpro delta`

Dynamic delta report (compare scans with git blame).

```
reconpro delta [-h] [--format {markdown,sarif}] [target]
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target (default: use last scan) |

**Options:**

| Option | Description |
|---|---|
| `--format {markdown,sarif}, -f {…}` | Delta output format |

**Examples:**

```bash
reconpro delta
reconpro delta --format sarif example.com  # (network)
```

### `reconpro graph`

Knowledge graph: attack surface, blast radius, chains.

```
reconpro graph [-h] [--action {stats,chains,surface,blast,export}] [target]
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target (default: use last scan) |

**Options:**

| Option | Description |
|---|---|
| `--action {stats,chains,surface,blast,export}, -a {…}` | Knowledge-graph action |

**Examples:**

```bash
reconpro graph
reconpro graph --action blast
reconpro graph --action chains
```

### `reconpro graph-visual`

Interactive D3.js knowledge graph visualization.

```
reconpro graph-visual [-h] [-o OUTPUT]
```

**Examples:**

```bash
reconpro graph-visual
reconpro graph-visual -o graph.html
```


## Scheduling, API server & workspaces

### `reconpro schedule`

Schedule recurring scans (network for non-local targets).

```
reconpro schedule [-h] [--every EVERY] [--modules MODULES] [--max-runs MAX_RUNS] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target domain, URL, or 'audit' |

**Options:**

| Option | Description |
|---|---|
| `--every EVERY, -e EVERY` | Interval: 30m, 1h, 6h, 1d |
| `--modules MODULES, -m MODULES` | Comma-separated module list (argparse shows no description) |
| `--max-runs MAX_RUNS` | Max runs (0=forever) |

**Examples:**

```bash
reconpro schedule example.com --every 1h  # (network)
reconpro schedule audit --every 1d  # local audit, no network
```

### `reconpro serve`

Start REST API server.

```
reconpro serve [-h] [--port PORT]
```

**Options:**

| Option | Description |
|---|---|
| `--port PORT, -p PORT` | API server port |

**Examples:**

```bash
reconpro serve
reconpro serve --port 7890
```

### `reconpro workspace`

Manage scan workspaces.

```
reconpro workspace [-h] [--targets TARGETS] [--format FORMAT] [{list,create,switch,delete,import,export}] [name]
```

**Arguments:**

| Argument | Description |
|---|---|
| `{list,create,switch,delete,import,export}` | Action |
| `name` | Workspace name |

**Options:**

| Option | Description |
|---|---|
| `--targets TARGETS, -t TARGETS` | Comma-separated targets (for create) |
| `--format FORMAT, -f FORMAT` | Export format (json/text) |

**Examples:**

```bash
reconpro workspace list
reconpro workspace create prod --targets a.com,b.com
reconpro workspace switch prod
```

### `reconpro notifications`

View notification center.

```
reconpro notifications [-h] [--level LEVEL] [--limit LIMIT] [--digest] [--clear] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--level LEVEL, -l LEVEL` | Filter by level (CRITICAL/WARNING/INFO/SUCCESS) |
| `--limit LIMIT, -n LIMIT` | Max notifications to show |
| `--digest, -d` | Show digest |
| `--clear` | Clear all notifications |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro notifications
reconpro notifications --digest --json
```


## Code & cloud audits

### `reconpro ast`

AST code analysis (Python/JS/TS vulnerability patterns). Note: pass a directory — a single file path is currently a no-op in the CLI.

```
reconpro ast [-h] [path]
```

**Arguments:**

| Argument | Description |
|---|---|
| `path` | File or directory to analyze |

**Examples:**

```bash
reconpro ast /path/to/code
```

### `reconpro iac`

Infrastructure-as-Code audit (Terraform/CF/Docker/K8s).

```
reconpro iac [-h] [--json] [path]
```

**Arguments:**

| Argument | Description |
|---|---|
| `path` | Directory to scan |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output JSON (stdout); human output goes to stderr |

**Examples:**

```bash
reconpro iac /path/to/infra
reconpro iac /path/to/infra --json
```

### `reconpro container`

Container escape analysis (Dockerfile + K8s).

```
reconpro container [-h] [--json] [path]
```

**Arguments:**

| Argument | Description |
|---|---|
| `path` | Directory to scan |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output JSON (stdout); human output goes to stderr |

**Examples:**

```bash
reconpro container /path/to/dockerfile-dir
reconpro container /path --json
```

### `reconpro cloud-recon`

Cloud infrastructure recon (AWS/Azure/GCP metadata + assets).

```
reconpro cloud-recon [-h] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target domain or 'local' for metadata probe |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output JSON (stdout); human output goes to stderr |

**Examples:**

```bash
reconpro cloud-recon local
reconpro cloud-recon example.com --json  # (network)
```

### `reconpro supply-chain`

Supply chain audit — GitHub repos or web content analysis (network).

```
reconpro supply-chain [-h] [--max-files MAX_FILES] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | GitHub repo (owner/repo) or URL to audit |

**Options:**

| Option | Description |
|---|---|
| `--max-files MAX_FILES` | Max files to scrape (GitHub) |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro supply-chain owner/repo  # (network)
reconpro supply-chain owner/repo --max-files 50 --json  # (network)
```


## Threat intelligence

### `reconpro cve`

CVE/NVD threat intelligence lookup (network).

```
reconpro cve [-h] [--limit LIMIT] query
```

**Arguments:**

| Argument | Description |
|---|---|
| `query` | Search query (e.g. 'SQL injection', 'CVE-2024-1234') |

**Options:**

| Option | Description |
|---|---|
| `--limit LIMIT, -n LIMIT` | Max rows to show |

**Examples:**

```bash
reconpro cve "SQL injection"  # (network)
reconpro cve CVE-2024-1234 --limit 5  # (network)
```

### `reconpro passive`

Passive DNS + historical intel (VirusTotal, Wayback) (network).

```
reconpro passive [-h] domain
```

**Arguments:**

| Argument | Description |
|---|---|
| `domain` | Domain to query |

**Examples:**

```bash
reconpro passive example.com  # (network)
```

### `reconpro geoip`

GeoIP enrichment for IP addresses (network).

```
reconpro geoip [-h] [--batch] [--json] ips [ips ...]
```

**Arguments:**

| Argument | Description |
|---|---|
| `ips` | IP addresses to enrich |

**Options:**

| Option | Description |
|---|---|
| `--batch` | Use batch API for multiple IPs |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro geoip 1.1.1.1  # (network)
reconpro geoip 1.1.1.1 8.8.8.8 --batch --json  # (network)
```

### `reconpro threat-feeds`

Threat feed ingestion and IP reputation checking (network).

```
reconpro threat-feeds [-h] [--refresh] [--stats] [--json] [ips ...]
```

**Arguments:**

| Argument | Description |
|---|---|
| `ips` | IPs to check (checks all feeds + DNSBLs) |

**Options:**

| Option | Description |
|---|---|
| `--refresh` | Force refresh all feeds |
| `--stats` | Show feed statistics only |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro threat-feeds 1.2.3.4  # (network)
reconpro threat-feeds --stats --json
reconpro threat-feeds --refresh  # (network)
```

### `reconpro ai-redteam`

AI endpoint discovery, vendor fingerprinting, secret extraction (network).

```
reconpro ai-redteam [-h] [--timeout TIMEOUT] [--insecure] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target domain or URL |

**Options:**

| Option | Description |
|---|---|
| `--timeout TIMEOUT` | Timeout (seconds) |
| `--insecure, -k` | Skip TLS verification |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro ai-redteam example.com  # (network)
reconpro ai-redteam example.com --json --timeout 30  # (network)
```

### `reconpro dark-web`

Monitor paste sites & threat feeds for credential leaks (network).

```
reconpro dark-web [-h] [--deep] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Domain, email, keyword, or IP to search |

**Options:**

| Option | Description |
|---|---|
| `--deep` | Enable deep scan (more sources) |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro dark-web example.com  # (network)
reconpro dark-web user@example.com --deep --json  # (network)
```

### `reconpro zero-day`

Hunt for zero-day vulnerability patterns in responses (network).

```
reconpro zero-day [-h] [--deep] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | URL or domain to hunt |

**Options:**

| Option | Description |
|---|---|
| `--deep` | Deep analysis mode |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro zero-day example.com  # (network)
reconpro zero-day example.com --deep --json  # (network)
```

### `reconpro attributor`

Attribute attack infrastructure to nation-state actors (network).

```
reconpro attributor [-h] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Domain, IP, or URL to attribute |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro attributor 1.2.3.4  # (network)
reconpro attributor example.com --json  # (network)
```


## Advanced analysis modules

### `reconpro netmap`

Network topology + trust mapping + lateral paths.

```
reconpro netmap [-h] [--subnet SUBNET]
```

**Options:**

| Option | Description |
|---|---|
| `--subnet SUBNET, -s SUBNET` | Subnet to scan (e.g. 192.168.1.0/24) |

**Examples:**

```bash
reconpro netmap
reconpro netmap --subnet 192.168.1.0/24
```

### `reconpro cross-validate`

Cross-validate ReconPro findings with independent verification.

```
reconpro cross-validate [-h] [--json] [target]
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Target (default: use last scan) |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro cross-validate
reconpro cross-validate --json example.com  # (network)
```

### `reconpro quantum-fingerprint`

OS & TCP stack fingerprinting via HTTP timing analysis (network).

```
reconpro quantum-fingerprint [-h] [-t TIMEOUT] [-k] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Domain or URL to fingerprint |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro quantum-fingerprint example.com  # (network)
reconpro quantum-fingerprint example.com -t 20 --json  # (network)
```

### `reconpro info-ops`

Information operations & deception analysis (defensive) (network).

```
reconpro info-ops [-h] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Domain or URL to analyze |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro info-ops example.com  # (network)
```

### `reconpro steg`

Detect hidden data in HTTP responses & images (network).

```
reconpro steg [-h] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | URL or domain to scan for steganography |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro steg example.com  # (network)
```

### `reconpro covert`

Detect & simulate covert channels (DNS/ICMP/timing) (network).

```
reconpro covert [-h] [--mode {detect,simulate}] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Domain or URL to analyze |

**Options:**

| Option | Description |
|---|---|
| `--mode {detect,simulate}` | detect or simulate covert channels |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro covert example.com  # (network)
reconpro covert example.com --mode simulate  # (network)
```

### `reconpro ghost`

Clone & ghost infrastructure for deception analysis (network).

```
reconpro ghost [-h] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Domain or URL to ghost |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro ghost example.com  # (network)
```

### `reconpro sigint`

Signal intelligence analysis of HTTP traffic patterns (network).

```
reconpro sigint [-h] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Domain or URL for SIGINT analysis |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro sigint example.com  # (network)
```

### `reconpro weaponized-report`

Generate weaponized decoy reports (defensive) (network for full run).

```
reconpro weaponized-report [-h] [--format {html,pdf,json}] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Domain or URL context |

**Options:**

| Option | Description |
|---|---|
| `--format {html,pdf,json}` | Output format |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro weaponized-report example.com  # (network)
reconpro weaponized-report example.com --format json  # (network)
```

### `reconpro honeypot`

Detect honeypots & score infrastructure legitimacy (network).

```
reconpro honeypot [-h] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Domain, IP, or URL to check |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro honeypot 1.2.3.4  # (network)
```

### `reconpro dead-drop`

Detect cryptographic dead drops in DNS/HTTP/CT logs (network).

```
reconpro dead-drop [-h] [--json] target
```

**Arguments:**

| Argument | Description |
|---|---|
| `target` | Domain or URL to scan |

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro dead-drop example.com  # (network)
```

### `reconpro fuzzer`

Context-aware payload fuzzing (network).

```
reconpro fuzzer [-h] [--param PARAM] [--category CATEGORY] url
```

**Arguments:**

| Argument | Description |
|---|---|
| `url` | Target URL to fuzz |

**Options:**

| Option | Description |
|---|---|
| `--param PARAM, -p PARAM` | Specific parameter to fuzz |
| `--category CATEGORY, -c CATEGORY` | Payload category (sqli, xss, ssti, ...) |

**Examples:**

```bash
reconpro fuzzer https://target/login  # (network)
reconpro fuzzer https://target/login -p q -c sqli  # (network)
```

### `reconpro rate`

Rate all v11 modules against industry tools /100.

```
reconpro rate [-h] [--module MODULE] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--module MODULE, -m MODULE` | Rate a specific module (e.g. dead-drop, quantum- |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro rate
reconpro rate --module dead-drop --json
```


## Defense & remediation

### `reconpro defense`

Generate deployable fixes (WAF rules, patches, IaC fixes) from a scan.

```
reconpro defense [-h] [-i INPUT]
```

**Examples:**

```bash
reconpro defense
reconpro defense -i scan.json
```

### `reconpro screenshot`

Take browser screenshot (needs: pip install reconpro[browser]) (network).

```
reconpro screenshot [-h] url
```

**Arguments:**

| Argument | Description |
|---|---|
| `url` | URL to screenshot |

**Examples:**

```bash
reconpro screenshot https://example.com  # (network)
```

### `reconpro open`

Open URL in browser (network).

```
reconpro open [-h] url
```

**Arguments:**

| Argument | Description |
|---|---|
| `url` | URL to open |

**Examples:**

```bash
reconpro open https://example.com  # (network)
```


## Engineering intelligence

### `reconpro engineering`

Run full engineering pipeline (health, drift, quality gates).

```
reconpro engineering [-h] [--json] [--repo REPO]
```

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |
| `--repo REPO` | Repository path to analyze |

**Examples:**

```bash
reconpro engineering
reconpro engineering --repo /path/to/repo --json
```

### `reconpro validate`

Validate a repository's engineering posture.

```
reconpro validate [-h] [--json] [--repo REPO]
```

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |
| `--repo REPO` | Repository path to validate |

**Examples:**

```bash
reconpro validate
reconpro validate --repo . --json
```

### `reconpro benchmark-engineering`

Benchmark the engineering pipeline.

```
reconpro benchmark-engineering [-h] [--quick] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--quick` | Quick benchmark subset |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro benchmark-engineering
reconpro benchmark-engineering --quick --json
```

### `reconpro recommendations`

Show engineering recommendations.

```
reconpro recommendations [-h] [--all] [--json] [--dismiss DISMISS]
```

**Options:**

| Option | Description |
|---|---|
| `--all` | Show all including dismissed |
| `--json` | Output as JSON |
| `--dismiss DISMISS` | Dismiss a recommendation by ID |

**Examples:**

```bash
reconpro recommendations
reconpro recommendations --json
reconpro recommendations --dismiss <ID>
```

### `reconpro memory`

Persistent engineering memory (facts).

```
reconpro memory [-h] [--recall RECALL] [--search SEARCH] [--stats] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--recall RECALL` | Recall a fact by key |
| `--search SEARCH` | Search facts by text |
| `--stats` | Show memory statistics |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro memory --stats
reconpro memory --search "flaky test"
reconpro memory --recall <KEY>
```

### `reconpro digital-twin`

System digital twin: capture state / detect anomalies.

```
reconpro digital-twin [-h] [--capture] [--anomaly] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--capture` | Capture current system state |
| `--anomaly` | Detect anomalies vs baseline |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro digital-twin --capture
reconpro digital-twin --anomaly --json
```

### `reconpro auto-fix`

Apply approved fixes (dry-run by default).

```
reconpro auto-fix [-h] [--apply] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--apply` | Apply approved fixes (dry-run by default) |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro auto-fix
reconpro auto-fix --apply
reconpro auto-fix --json
```

### `reconpro regression`

Regression detection vs a baseline.

```
reconpro regression [-h] [--baseline] [--detect] [--report] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--baseline` | Capture new baseline |
| `--detect` | Detect regressions vs baseline |
| `--report` | Generate regression report |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro regression --baseline
reconpro regression --detect
reconpro regression --report
```

### `reconpro health`

Show module health scores and circuit breaker status.

```
reconpro health [-h] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro health
reconpro health --json
```

### `reconpro deps`

Visualize module dependency graph.

```
reconpro deps [-h] [--modules MODULES] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--modules MODULES, -m MODULES` | Comma-separated module list (default: all) |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro deps
reconpro deps --modules recon,auth --json
```

### `reconpro info`

Module help, diagnostics, and version info.

```
reconpro info [-h] [--module MODULE] [--modules] [--diagnose] [--health] [--version] [--examples] [--quick-start] [--json]
```

**Options:**

| Option | Description |
|---|---|
| `--module MODULE, -m MODULE` | Show detailed help for a module (e.g. quantum- |
| `--modules` | List all modules with descriptions |
| `--diagnose` | Run full system diagnostics |
| `--health` | Quick health check |
| `--version, -v` | Detailed version information |
| `--examples` | Show usage examples |
| `--quick-start` | Show quick-start guide |
| `--json` | Output as JSON |

**Examples:**

```bash
reconpro info
reconpro info --modules
reconpro info --module quantum-fingerprint
reconpro info --quick-start
reconpro info --version
```


