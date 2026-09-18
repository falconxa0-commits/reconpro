/**
 * Basic reconpro-sdk usage: version ping + typed scan result + export.
 *
 * Run:  bun run examples/basic.ts [target]
 *
 * Binary resolution: `RECONPRO_BINARY` env → "reconpro" on PATH. For a fully
 * offline demo without the real CLI installed, point it at the test stub:
 *
 *   RECONPRO_BINARY=tests/fixtures/reconpro-stub.mjs bun run examples/basic.ts
 *
 * By default it scans a nonexistent `*.invalid` target — fully offline (the
 * CLI truth layer short-circuits unreachable targets instantly), so this
 * example needs no network access. Pass a real target for a live scan.
 */

import {
  ReconProClient,
  ReconProError,
  UNREACHABLE_TARGET,
} from "../src/index.js";

const target = process.argv[2] ?? "nonexistent-demo.invalid";
const client = new ReconProClient();

try {
  console.log(`version         : ${await client.version()}`);

  const result = await client.scan(target);
  console.log(`target          : ${result.target}`);
  console.log(`grade           : ${result.grade} (score ${result.totalScore})`);
  console.log(`total findings  : ${result.totalFindings}`);
  console.log(`severity counts : ${JSON.stringify(result.severityCounts)}`);
  if (result.targetValidation !== null) {
    const tv = result.targetValidation;
    console.log(
      `target state    : ${tv.state} (dns=${tv.dnsResolved} reachable=${tv.reachable} http_ok=${tv.httpOk})`,
    );
  }
  if (result.scanMetadata !== null) {
    console.log(
      `scan            : ${result.scanMetadata.result} in ${result.scanMetadata.durationS}s`,
    );
  }
  for (const f of result.findings.slice(0, 3)) {
    console.log(`  - [${f.severity}] ${f.title}`);
    console.log(
      `    confidence=${f.confidence} verification_state=${f.verificationState}`,
    );
  }
  if (result.unreachable) {
    console.log(
      `truth layer     : no claims made about an unreachable target (state=${UNREACHABLE_TARGET})`,
    );
  }

  // Export the last scan (format from the extension; default path in tmpdir).
  const report = await client.exportReport("sarif");
  console.log(`export          : ${report}`);

  // Unknown/future JSON keys stay reachable via `raw`.
  console.log(
    `raw keys sample : ${Object.keys(result.raw).slice(0, 4).join(", ")}...`,
  );
} catch (err) {
  if (err instanceof ReconProError) {
    console.error(
      `sdk error [${err.code}] exit=${err.exitCode}: ${err.message}`,
    );
    if (err.stderr) console.error(`stderr: ${err.stderr.slice(0, 300)}`);
    process.exit(1);
  }
  throw err;
}
