# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning.

## [Unreleased]

### Fixed

- TypeScript/JavaScript taint sources now cover URL-named fields
  destructured in function signatures (`_fetch({ url, headers })`,
  `({ url }: RequestPayload) => ...`) and in destructuring assignments
  (`const { url } = payload`), so a payload-field URL reaching a
  redirect-following `fetch`/`axios`/`got` now fires G0/G6 instead of
  going dark. The site-probe source probe marks the same functions as
  entry candidates. Real-world gap seen on zcaceres/fetch-mcp:
  `Fetcher._fetch` now reports deterministic G6.

### Added

- Corpus: `g0-smolagents-visit-webpage` (Apache-2.0, smolagents
  `default_tools.py` at 96f33faa): `VisitWebpageTool.forward(url)` is a
  bare `requests.get(url)` on a model-chosen tool argument with full
  read-back. `g1-uptime-kuma-browser-monitor` (MIT, uptime-kuma at
  b61b322c): `RealBrowserMonitorType.check()` scheme-checks then
  `page.goto(monitor.url)` in headless Chromium with no host/range check
  and unchecked redirects (verified live on loopback, screenshot exfil
  channel), plus the `webhook.js` axios redirect-follow shape.

### Changed

- Corpus: `clean-zcaceres-fetch-mcp` renamed to
  `g6-zcaceres-fetch-mcp-redirect` with `expected: [G6]`. Its post-fetch
  `response.url` re-check happens after the redirect hop connects, so it
  is a partial guard, not a clean exemplar. `CLEAN` rows are now
  documented in the README as "no deterministic class under current
  ceilings", not a claim of complete SSRF defense.
- Docs: `docs/source-sink-matrix.md` documents the destructured-field
  source and a new blind spot for factory-mounted / session-adapter
  guards (a `requests.Session` mounted with a guarded adapter is
  invisible at the call site).

## [0.1.0] - 2026-10-09

### Added

- `ssrf-guard-audit scan <path>` CLI: runs the packaged Semgrep rule pack over
  a cloned repo and resolves every enumerated sink site into a deterministic
  finding, recognized-complete (version-scoped), unrecognized-guard
  (manual review), or G0. Text output prints findings grouped by class, then
  the G7/G9/G10 manual-audit checklist, then the coverage summary (files
  scanned per language, entry-point candidates, sinks inside/outside
  recognized entries, parse failures, site counts, "no SSRF-relevant surface
  detected" verdict). `--json` emits the versioned schema
  (`ssrf-guard-audit/v1`, taxonomy `g0-g10/v1`). Exit codes: 0 clean or
  checklist-only, 1 findings or unrecognized guards, 2 operational failure.
  `--timeout` sets the per-file Semgrep timeout.
- Deterministic Semgrep rules for G0-G6 and G8: `rules/python/` (G0, G1,
  G2, G3, G5, G6, and three G8 shapes) and `rules/typescript/`
  (G0-G6 and G8; `languages: [typescript, javascript]`, so `.js`/`.mjs`/
  `.cjs` are covered). Each rule carries `metadata.guard_class` and
  `advisory_refs` anchoring it to an advisory or audited code shape.
- Generalized source vocabulary covering caller-shaped URL input across
  entry-point families: URL-named parameters and field reads, request-object
  members, web route decorators and framework registrations, tool/agent
  registrations, verb-named route handlers, dispatch methods, and tool-class
  entry methods. `docs/source-sink-matrix.md` is the authoritative contract.
- `rules/checklist/`: search-mode candidate enumerators for the structural
  classes (G7 resolver sites, G9 entry points, G10 credential attach sites),
  emitted only when SSRF-relevant surface is detected.
- `rules/site-probes/`: entry-point and network-sink enumerators, the
  complete-guard shape probe, and the intervening-validation probe consumed
  by the layered site resolution.
- `ssrf-guard-audit corpus-validate` subcommand (`--corpus`, `--json`,
  `--timeout`): runs the packaged rules over every labeled sample in
  `corpus/manifest.jsonl` and reports caught, missed, misclassified-extra,
  clean, and precision-failure statuses; checklist-tier labels are validated
  by checklist emission and reported separately from deterministic
  pass/fail. Unmaterialized fetched samples are skipped; exits 1 on any
  miss, precision failure, or missing checklist emission.
- Labeled corpus under `corpus/` (CC BY 4.0): 16 instances / 22 samples
  covering every claimed class plus CLEAN exemplars, spanning MCP tool
  servers, webhooks (frappe), link/URL validation (anything-llm), agent
  browser tools (gptme), and SSRF-safe adapter internals (crewAI), with
  `manifest.jsonl` per-sample labels, generated `EXPECTEDRESULTS.csv`
  rollup, per-instance `metadata.json`, and `NOTICE` attribution.
  `scripts/fetch_corpus.py` materializes fetched instances at pinned SHAs.
- `docs/taxonomy.md`: the G0-G10 class definitions and the shared
  complete-means pipeline.
- Scan hardening: target `.gitignore`/`.semgrepignore` files are disabled
  and surfaced in coverage; default excludes cover `node_modules`, `dist`,
  `build`, `vendor`, `third_party`, `venv`, `.venv`; findings under test or
  example paths are flagged, not dropped. No network access and no target
  code execution during scans.
- CI: `semgrep validate`, `semgrep test`, and `pytest` on pinned Semgrep
  1.177.0; a gate asserting no `corpus/` file is collected by pytest;
  generation of the single-file `dist/ssrf-guard-audit.yaml` bundle for
  `semgrep --config <raw-url>` consumption.
