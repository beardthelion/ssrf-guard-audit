# G0-G10 guard-completeness taxonomy

This document defines the class set `ssrf-guard-audit` reports. A finding is
always a *site*: an outbound request call inside one entry-point extent,
resolved against the classes below in precedence order. The taxonomy version
reported in JSON output is `g0-g10/v1`.

## What "complete" means

For every class, a complete guard is the same four-step pipeline:

1. **Resolve all addresses** for the hostname (`getaddrinfo`-family, not a
   single-answer lookup).
2. **Range-check every resolved address** against public-routability
   (reject loopback, private, link-local, CGNAT, multicast, reserved, and
   IPv4-mapped IPv6 addresses).
3. **Connect to the validated address** (connect-time pinning) so a DNS
   answer cannot change between check and connect.
4. **Re-validate every redirect hop** before connecting to it.

Anything less is incomplete. The deterministic rules (G0-G6, G8) name
recognizable incomplete shapes. G7, G9, and G10 are manual-review checklist
classes: they cannot be decided intra-function, so they emit candidates, not
findings.

## G0: no guard

A caller-shaped URL input reaches an outbound request call with no recognized
complete-guard call on the intra-function taint path. Unrecognized or weak
guards do not suppress G0: they keep the raw finding, which site resolution
relabels as a weaker class or as `unrecognized_guard` when evidence exists.

## G1: scheme/protocol-only checks

The path validates only the scheme (`http`/`https` allowlist, `startsWith
("https://")`, `urlparse(url).scheme` membership) and never checks the host.
`https://169.254.169.254/latest/meta-data` passes every scheme check.

## G2: string blocklists

The tainted host is compared against literal names (`localhost`,
`127.0.0.1`, `.internal`) or regex/literal blocklists without DNS
resolution. Blocklists miss decimal/octal/hex IP spellings, DNS names that
resolve to internal addresses, IPv6, and every range the list forgot.

## G3: IP parsing without DNS resolution

The check parses the URL's host as an IP literal (`ipaddress.ip_address`,
`net.isIP`) and stops there. A hostname that is not a literal (any DNS name
pointing at an internal address, including attacker-controlled rebinding
domains) skips the check entirely.

## G4: bracketed IPv6 bypass

TypeScript/JavaScript specific: `net.isIP`-family checks receive
`new URL(url).hostname` unchanged, and URL parsers keep the `[` `]` on
IPv6 literals. `isIP("[::1]")` returns 0, so a bracketed loopback sails
past the private-range branch.

## G5: incomplete IPv6 normalization

IPv6 handled textually instead of structurally: `::ffff:` `startswith`/
`removeprefix`/`replace` tricks, or a prefix branch plus tail extraction
feeding an IPv4 check. These miss hextet-normalized `::ffff:7f00:1`, NAT64
`64:ff9b::`, and 6to4 `2002:` forms.

## G6: missing redirect re-validation

The request follows redirects (default behavior for `requests`, `fetch`,
`axios`, `got`, `page.goto`, `*client*`/`*session*` methods) and no hop is
re-validated. The initial URL may be checked; the redirect target is not.
Entry-level `allow_redirects=False` plus a manual re-validated hop loop is
the complete shape.

## G7: DNS rebinding / TOCTOU

Resolve-then-validate-then-connect has a window: a hostname can answer a
public address during validation and a private address at connect time
(DNS rebinding, short TTL flips). Checklist class: every resolver call site
is emitted for manual verification that the connect pins the validated
address (or that the connected peer is re-checked after connect, which the
firecrawl `safeFetch` connect hook demonstrates).

## G8: weak, unanchored, or default-off allowlists

Allowlist checks that are unanchored (`host.endswith("example.com")`
matches `notexample.com`; `url.startswith("https://api.example.com")`
matches `api.example.com.evil.net`), gated behind an env var bypass
(`COLLECTOR_ALLOW_ANY_IP`, `DISABLE_SSRF`), default-off (empty default
allowlists that permit everything), or fail-open (`length === 0` checks that
pass when the list is unset).

## G9: guard coverage across entry points

Checklist class. Every recognized entry point is emitted so a reviewer can
verify that every path from entry to sink shares the same complete guard:
a fetch tool with a guard and a second tool that fetches without one are
two sites, not one averaged verdict.

## G10: credentials on a caller-chosen host

Checklist class. `Authorization` headers, `auth` kwargs, credential-keyed
objects, and `headers.set(...)` attach sites are emitted so a reviewer can
confirm credentials never ride a request to a host the caller chose.
Credential forwarding to a fixed operator-controlled host is fine; to a
caller-chosen host it leaks secrets to whoever controls the DNS answer.
