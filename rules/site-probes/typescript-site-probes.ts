// Semgrep test fixture for rules/site-probes/typescript-site-probes.ts.
// Annotations are the executable contract (semgrep test). These rules are
// enumerators: every match is a location mark, never a verdict.

declare const server: any;
declare const fetch: any;
declare const axios: any;
declare const page: any;

// ruleid: ssrf-guard-audit-probe-handler-source-typescript
server.tool("fetch", async ({ url }: { url: string }) => {
  // ruleid: ssrf-guard-audit-probe-network-sink-typescript
  return fetch(url);
});

// ruleid: ssrf-guard-audit-probe-handler-source-typescript
server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  const url = request.params.arguments.url;
  // ruleid: ssrf-guard-audit-probe-complete-guard-typescript
  const checked = await safeFetch(url);
  // ruleid: ssrf-guard-audit-probe-network-sink-typescript
  return axios.get(checked);
});

// ruleid: ssrf-guard-audit-probe-handler-source-typescript
server.registerTool("browse", async ({ url }: { url: string }) => {
  // ruleid: ssrf-guard-audit-probe-intervening-validation-typescript
  validateUrl(url);
  // ruleid: ssrf-guard-audit-probe-intervening-validation-typescript
  if (!ok) {
    throw new Error("blocked");
  }
  // ruleid: ssrf-guard-audit-probe-network-sink-typescript
  return page.goto(url);
});

// ruleid: ssrf-guard-audit-probe-handler-source-typescript
function noSurface(url: string): string {
  // ok: ssrf-guard-audit-probe-network-sink-typescript
  return render(url);
}

// Dispatch-method extent: class-based tool registry shape.
class NavigateTool {
  // ruleid: ssrf-guard-audit-probe-handler-source-typescript
  async execute(args: any, ctx: any) {
    // ruleid: ssrf-guard-audit-probe-network-sink-typescript
    return fetch(args.url);
  }
}

// Object-literal dispatch callback (addTool-style registration).
const registry2 = {
  name: "fetch",
  // ruleid: ssrf-guard-audit-probe-handler-source-typescript
  execute: async (args: any) => {
    // ruleid: ssrf-guard-audit-probe-network-sink-typescript
    return axios.get(args.url);
  },
};

// Negative: non-URL-named member read inside an unrecognized method.
class OtherTool {
  // ok: ssrf-guard-audit-probe-handler-source-typescript
  async execute(payload: any) {
    // ruleid: ssrf-guard-audit-probe-network-sink-typescript
    return fetch(payload.item);
  }
}
