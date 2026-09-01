#!/usr/bin/env node
//
// Verifies that the extension's diagnostics.js produces the same URL digests as
// the detector and reviewer.
//
// The digest is what joins a case across the escalation hop. If the JavaScript
// canonicalization drifts from the Python one, nothing throws — correlation just
// silently stops working — so this check exists to make that drift loud.
//
// The Python implementations are pinned against these same values in each
// repo's tests/test_observability.py. Keep all three lists in step.
//
// Usage:  node deploy/observability/check-digest-parity.mjs [path/to/diagnostics.js]

import { readFileSync } from "node:fs";
import { argv, exit } from "node:process";

const GOLDEN = {
  "https://Example.COM:443/Login?b=2&a=1#frag": "f5e1bdeacac536ca",
  "https://example.com/Login?a=1&b=2": "f5e1bdeacac536ca",
  "http://example.com:80/": "2a1b402420ef4657",
  "https://example.com": "0f115db062b7c0dd",
  "https://sub.example.co.uk/path?z=9&a=0": "c368c4f6ed377c46",
};

// From deploy/observability/ up to the repo root, then across to a sibling
// checkout of the extension repository.
const DEFAULT_PATH = "../../../phishingshield-persian/diagnostics.js";
const target = argv[2] ?? new URL(DEFAULT_PATH, import.meta.url).pathname;

let source;
try {
  source = readFileSync(target, "utf8");
} catch (error) {
  console.error(`could not read ${target}`);
  console.error("pass the path explicitly if the extension repo lives elsewhere:");
  console.error("  node check-digest-parity.mjs /path/to/phishingshield-persian/diagnostics.js");
  exit(2);
}

// diagnostics.js is an IIFE that attaches itself to the global it is handed.
const host = {};
new Function("self", source)(host);
const diagnostics = host.__PhishingShieldDiagnostics;

if (!diagnostics || typeof diagnostics.urlDigest !== "function") {
  console.error("diagnostics.js did not expose urlDigest()");
  exit(2);
}

let failures = 0;
for (const [url, expected] of Object.entries(GOLDEN)) {
  const actual = await diagnostics.urlDigest(url);
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`${ok ? "ok  " : "FAIL"}  ${actual}  ${ok ? "" : `(expected ${expected}) `}${url}`);
}

if (failures) {
  console.error(
    `\n${failures} digest(s) diverged from the Python services. ` +
      "Cross-service trace correlation is broken until this is fixed."
  );
  exit(1);
}
console.log(`\nall ${Object.keys(GOLDEN).length} digests match the Python implementations`);
