#!/usr/bin/env node
// Basic reconpro-sdk usage.  Run:  node examples/basic.mjs [--offline]

import { ReconProClient, SdkError } from '../src/index.js';

const offline = process.argv.includes('--offline');
const client = new ReconProClient();

try {
  console.log(`version: ${await client.version()}`);
  const report = await client.doctor();
  console.log(`doctor: grade=${report.grade} findings=${report.total_findings}`);
  console.log(`history: ${(await client.history()).split('\n')[0]}`);
  if (offline) {
    console.log('scan skipped (--offline)');
  } else {
    const result = await client.scan('example.com');
    console.log(`scan: ${JSON.stringify(result).slice(0, 200)}...`);
  }
} catch (err) {
  if (err instanceof SdkError) {
    console.error(`sdk error (exit ${err.exitCode}): ${err.message}`);
    process.exit(1);
  }
  throw err;
}
