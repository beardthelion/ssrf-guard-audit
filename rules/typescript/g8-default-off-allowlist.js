// Semgrep test fixture for ssrf-guard-audit-g8-typescript (plain JS variant).

// Positive: env kill switch and the gate that consumes it.
// ruleid: ssrf-guard-audit-g8-typescript
const DISABLE_SSRF_GUARD = process.env.MCP_FETCH_DISABLE_SSRF_GUARD === "1";

async function isSafeUrl(input) {
  const u = new URL(input);
  // ruleid: ssrf-guard-audit-g8-typescript
  if (DISABLE_SSRF_GUARD) {
    return { ok: true, url: u };
  }
  const hostname = u.hostname;
  return net.isIP(hostname) === 0;
}

// Positive: allow-private env override with empty default.
// ruleid: ssrf-guard-audit-g8-typescript
const ALLOW_PRIVATE = process.env.AUTH_FETCH_ALLOW_PRIVATE ?? "";

// Positive: empty-default allowlist and unanchored suffix check.
// ruleid: ssrf-guard-audit-g8-typescript
const allowed = opts.allowedDomains || [];

function allowlistOk(input) {
  const h = new URL(input).hostname;
  // ruleid: ssrf-guard-audit-g8-typescript
  return allowed.some((d) => h.endsWith(d));
}

// Negative: benign env reads and anchored matching.
// ok: ssrf-guard-audit-g8-typescript
const home = process.env.HOME || "";

function anchored(input, allowedList) {
  const h = new URL(input).hostname;
  // ok: ssrf-guard-audit-g8-typescript
  return allowedList.some((d) => h === d || h.endsWith("." + d));
}
