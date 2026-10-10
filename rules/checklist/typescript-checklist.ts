// Semgrep test fixture for rules/checklist/typescript-checklist.yaml.
// Annotations are the executable contract (semgrep test). Checklist rules
// enumerate manual-review candidates; every hit is a candidate, not a
// verdict.

declare const server: any;
declare const dns: any;
declare const fetch: any;
declare const res: any;

// ruleid: ssrf-guard-audit-checklist-g9-typescript
server.registerTool("fetch", async ({ url, host }: any) => {
  // ruleid: ssrf-guard-audit-checklist-g7-typescript
  const addr = await dns.lookup(host);
  // ruleid: ssrf-guard-audit-checklist-g10-typescript
  return fetch(url, { headers: { Authorization: "Bearer t" } });
});

// ruleid: ssrf-guard-audit-checklist-g9-typescript
server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  // ruleid: ssrf-guard-audit-checklist-g7-typescript
  const infos = await resolver.resolve4(request.params.host);
  // ruleid: ssrf-guard-audit-checklist-g10-typescript
  res.setHeader("Authorization", `Bearer ${request.params.token}`);
  return null;
});

function noSurface(x: any): number {
  // ok: ssrf-guard-audit-checklist-g7-typescript
  // ok: ssrf-guard-audit-checklist-g9-typescript
  // ok: ssrf-guard-audit-checklist-g10-typescript
  return x.length;
}
