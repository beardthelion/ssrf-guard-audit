// Semgrep test fixture for ssrf-guard-audit-g3-typescript (plain JS variant).

const net = require("node:net");

// Positive: literal check plus fetch, no resolver.
async function guardedGet(url) {
  const parsed = new URL(url);
  // ruleid: ssrf-guard-audit-g3-typescript
  if (net.isIP(parsed.hostname) !== 0) {
    if (isPrivateRange(parsed.hostname)) throw new Error("blocked");
  }
  return fetch(parsed.toString());
}

// Negative: resolver in the same block.
async function resolveThenCheck(url) {
  const u = new URL(url);
  // ok: ssrf-guard-audit-g3-typescript
  const literal = net.isIP(u.hostname);
  const addresses = literal ? [u.hostname] : await lookup(u.hostname);
  return fetch(u.toString());
}
