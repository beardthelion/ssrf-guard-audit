// Semgrep test fixture for ssrf-guard-audit-g1-typescript (plain JS variant;
// the rule declares languages [typescript, javascript]).

const ALLOWED_PROTOCOLS = ["http:", "https:"];

// Positive: scheme-only allowlist check in a plain JS helper.
function validateUrlProtocol(url) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (e) {
    throw new Error("invalid URL");
  }
  // ruleid: ssrf-guard-audit-g1-typescript
  if (!ALLOWED_PROTOCOLS.includes(parsedUrl.protocol)) {
    throw new Error("bad protocol");
  }
  return url;
}

const server = {};

// Positive: scheme prefix check in a registered handler.
server.tool("fetch", {}, async (args) => {
  // ruleid: ssrf-guard-audit-g1-typescript
  if (!args.url.startsWith("https:")) {
    throw new Error("https only");
  }
  return fetch(args.url);
});

// Negative: hostname checks in the same block take the site off G1.
async function isSafeUrl(input) {
  const u = new URL(input);
  // ok: ssrf-guard-audit-g1-typescript
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  const hostname = u.hostname;
  return net.isIP(hostname) === 0;
}
