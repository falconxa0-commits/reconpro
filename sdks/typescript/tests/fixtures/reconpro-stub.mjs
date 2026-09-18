#!/usr/bin/env node
// Stub `reconpro` binary for hermetic tests and offline example runs.
//
// Emits canned JSON byte-faithful to `reconpro scan <x>.invalid --json` on
// CLI 11.2.0 (plus an unknown "future_field" key to pin forward-compat).
// No network, no real CLI required. Driven entirely by its arguments:
//
//   --version                       → "ReconPro 11.2.0" on stdout, exit 0
//   scan|vibesec <target> --json     → canned unreachable-target JSON
//   scan|vibesec <t> --json -o FILE  → same JSON written ONLY to FILE
//   audit|dev|doctor --json          → canned local-scan JSON
//   export <path>                    → writes a placeholder report file
//
// Magic targets (used by the error-path tests/examples — all through the
// real public SDK API, no fake injection points):
//   target contains "fail"    → exit 2 with a usage error on stderr
//   target contains "garbage" → prints "this is not json" (invalid JSON)
//   target contains "sleep"   → hangs for 10 s (timeout tests)

import { writeFileSync } from "node:fs";

const args = process.argv.slice(2);

const UNREACHABLE = (target) => ({
  target,
  modules_run: [],
  total_findings: 1,
  severity_counts: { info: 1 },
  total_score: 0,
  grade: "U",
  badge_markdown: "![ReconPro U](...)",
  vibesec_score: null,
  vibesec_grade: null,
  module_results: {},
  findings: [
    {
      title: `Target unreachable — scan not performed: ${target}`,
      severity: "info",
      category: "target_validation",
      module: "engine",
      description:
        "The target validation pipeline could not verify the target, so no vulnerability modules were executed. This is an honest no-result: no security claims are made about an unreachable target.",
      evidence: "state=UNREACHABLE_TARGET; DNS resolution failed: [Errno -2] Name or service not known",
      asset: target,
      points_deducted: 0,
      remediation:
        "Verify the target hostname is correct and authorized, that DNS resolves from this network, and that the host allows inbound connections on HTTP(S) ports.",
      dread_score: 0.0,
      confidence: 0.95,
      verification_state: "UNREACHABLE_TARGET",
    },
  ],
  intelligence: null,
  engineering: null,
  quality: null,
  engineering_score: 0.0,
  target_validation: {
    state: "UNREACHABLE_TARGET",
    dns_resolved: false,
    reachable: false,
    http_ok: false,
    tls_valid: null,
    details: {
      host: target,
      dns: { ok: false, ips: [], error: "[Errno -2] Name or service not known", is_ip_literal: false },
      reason: "DNS resolution failed: [Errno -2] Name or service not known",
    },
    checked_at: "2026-09-18T00:35:16.676717+00:00",
  },
  scan_metadata: {
    scanner: "reconpro",
    started_at: "2026-09-18T00:35:16.676717+00:00",
    duration_s: 0.01,
    result: "unreachable_target_short_circuit",
  },
  future_field: { anything: ["the", "CLI", "may", "add"] },
});

const LOCAL = {
  target: "",
  modules_run: ["dev"],
  total_findings: 0,
  severity_counts: {},
  total_score: 100,
  grade: "A+",
  findings: [],
  target_validation: null,
  scan_metadata: {
    scanner: "reconpro",
    started_at: "2026-09-18T00:35:16.676717+00:00",
    duration_s: 0.1,
    result: "ok",
  },
};

if (args.includes("--version")) {
  process.stdout.write("ReconPro 11.2.0\n");
  process.exit(0);
}

const command = args[0];

if (command === "export") {
  const path = args[1];
  if (!path) {
    process.stderr.write("usage: export <path>\n");
    process.exit(2);
  }
  writeFileSync(path, '{"stub": true, "format": "auto-detected"}\n');
  process.exit(0);
}

if (command === "scan" || command === "vibesec") {
  const target = args[1] ?? "";
  if (target.includes("fail")) {
    process.stderr.write("usage: boom (stub usage error)\n");
    process.exit(2);
  }
  if (target.includes("garbage")) {
    process.stdout.write("this is not json\n");
    process.exit(0);
  }
  if (target.includes("sleep")) {
    setTimeout(() => process.exit(0), 10_000);
    process.exitCode = 0;
  } else {
    const payload = `${JSON.stringify(UNREACHABLE(target), null, 2)}\n`;
    const oIndex = args.indexOf("-o");
    if (oIndex !== -1 && args[oIndex + 1]) {
      // Real CLI quirk: with -o the JSON goes ONLY to the file.
      writeFileSync(args[oIndex + 1], payload);
    } else {
      process.stdout.write(payload);
    }
    process.exit(0);
  }
} else if (command === "audit" || command === "dev" || command === "doctor") {
  process.stdout.write(`${JSON.stringify(LOCAL, null, 2)}\n`);
  process.exit(0);
} else {
  process.stderr.write(`usage: reconpro-stub: unknown command ${JSON.stringify(command ?? "(none)")}\n`);
  process.exit(2);
}
