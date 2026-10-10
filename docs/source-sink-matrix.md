# Source/sink matrix

This file is the documented detection boundary for the deterministic rules
under `rules/`. Every rule in the pack cites this file; the source, sink, and
sanitizer lists below are the contract the rules encode. If a rule and this
document disagree, the document is wrong until the rule changes.

The rules run on Semgrep Community Edition in taint mode. A G0 finding means:
a value derived from a caller-shaped URL input reaches an outbound request call
within one function body, and no recognized complete-guard call intervenes.

## Sources: caller-shaped URL input

A source is a value a remote caller (or an upstream model) can plausibly
shape: a parameter of a function registered as an entry point, a
URL-named parameter, or a URL-named field read off a config, request, or
payload object. "Entry point" covers every family the rules know: web
route decorators and framework registrations, MCP-style tool
registrations, verb-named route handlers, dispatch methods, and tool-class
entry methods.

### Python (`ssrf-guard-audit-g0-python` and later `rules/python/*`)

A parameter of a `def` or `async def` is a source when:

- Its name is URL-shaped (case-insensitive): `url`, `uri`, `href`,
  `link`, `endpoint`, `callback`, `callback_url`, `webhook`,
  `webhook_url`, `jwks_uri`, `jwks_url`, `avatar_url`, `image_url`,
  `feed_url`, `target`, or `host`. Suffix forms also match:
  `page_url`, `callbackUrl`, `feed_url`, `site_url`, `imageUrl`, and the
  same camel halves (`Url`, `Uri`, `Href`, `Endpoint`, `Webhook`). The
  camel halves are matched case-sensitively so `curl` and friends stay
  out.
- The function carries a route decorator: `@<anything>.route`,
  `@<anything>.api_route`, `@<anything>.get|post|put|delete|patch|head|
  options|websocket`, `@<anything>.add_url_rule`, `@<anything>.api_view`,
  `@<anything>.action`, and the same names bare (`@route`, `@get`, ...),
  with or without call parens. Every parameter is a source.
- The function carries a tool-entry decorator: `@<anything>.tool`,
  `@<anything>.call_tool`, `@<anything>.get_prompt`, and the bare-name
  forms. Every parameter is a source; a tainted `arguments` dict taints
  every value extracted from it.
- The function is a dispatcher: its name starts with `execute`, `handle`,
  `dispatch`, `process`, `invoke`, `run`, or `call`, and one parameter is
  named `args`, `arguments`, `params`, `request`, or `input`.
- The function is a tool-entry method on a class whose name contains
  `tool` (case-insensitive): `forward`, `run`, `arun`, `call`,
  `execute`, `invoke`, `process`, or a name beginning with those, with an
  optional leading underscore (`_run`, `_execute`). Every parameter
  besides `self`/`cls` is a source, including `**kwargs`.

An expression is a source when it reads a URL-shaped field:

- `<obj>.<member>` where the member is `url`, `uri`, `href`, `link`,
  `endpoint`, `callback_url`, `webhook_url`, `jwks_uri`, `jwks_url`,
  `avatar_url`, `image_url`, `feed_url`, `target`, or `host`
  (case-insensitive). Covers `cfg.webhook_url`, `options.url`,
  `request.url`, `self.request_url`.
- `<obj>["<key>"]` or `<obj>.get("<key>", ...)` where the literal key is
  in that same set. Covers `config["webhook_url"]`, `args["url"]`,
  `kwargs.get("feed_url")`.
- On a `request`/`req` receiver (or a dotted chain ending in one, such as
  `self.request`), reads of `args`, `GET`, `POST`, `query_params`,
  `path_params`, `form`, `data`, `json`, `params`, `values`, `query`, or
  `body` (case-sensitive member names, so `.get()` calls and `dict.get`
  helpers are not sources).

### TypeScript and JavaScript (`ssrf-guard-audit-g0-typescript` and later `rules/typescript/*`)

A parameter is a source when:

- Its name is URL-shaped: the same list as Python (`url`, `uri`, `href`,
  `link`, `endpoint`, `callback`, `callback_url`, `webhook`,
  `webhook_url`, `jwks_uri`, `jwks_url`, `avatar_url`, `image_url`,
  `feed_url`, `target`, `host`, case-insensitive), plus the same suffix
  and camel-half forms.
- The enclosing function is a verb-named handler: `GET`, `POST`, `PUT`,
  `DELETE`, `PATCH`, `HEAD`, or `OPTIONS` (function declaration or arrow
  assigned to the name), and the parameter is named `req`, `request`,
  `ctx`, or `event`. The Next.js route-handler shape.
- The enclosing callback is passed to a framework verb call:
  `<recv>.get|post|put|delete|del|patch|head|options|all|use|route|ws`
  (case-insensitive), arrow or `function` callback. Every callback
  parameter is a source, so `app.get("/p", (req, res) => ...)` taints
  `req`.
- The enclosing callback is passed to a tool-registration method named
  `tool`, `registerTool`, `callTool`, `getPrompt`, `setRequestHandler`,
  `prompt`, or `resource`, on any receiver. Arrow functions with block or
  expression bodies, `function` expressions, and object-destructured
  parameters (`async ({ url }) => ...`, `async ({ url }: T) => ...`) are
  covered; destructured fields become individual sources.
- The enclosing function is a dispatcher: a method, function declaration,
  or object-literal callback whose name starts with `execute`, `handle`,
  `dispatch`, `process`, `invoke`, `run`, or `call`, with a parameter
  named `args`, `arguments`, `params`, `request`, or `input`.
- The enclosing signature destructures a URL-named object field in a
  parameter: `function f({ url, headers })`,
  `async _fetch({ url }: RequestPayload)`, arrow or method form, typed or
  not. The parameter itself is an object, but the field binding is a
  source for the whole body. Covers `_fetch({ url, headers, proxy })`.

An expression is a source when it reads a caller-shaped field:

- `<obj>.<member>` where the member is in the URL set above
  (case-insensitive). Covers `cfg.webhookUrl`, `opts.url`,
  `req.url`, `this.target`.
- `<obj>["<key>"]` or `<obj>.get("<key>", ...)` for the same names.
  Covers `config["webhook_url"]`, `args["url"]`,
  `searchParams.get("feedUrl")`.
- On a `req`/`request`/`ctx` receiver (or a dotted chain ending in one),
  reads and calls of `query`, `body`, `params`, `param`, `querystring`,
  `nextUrl`, `searchParams`, `formData`, `data`, `json`, `args`, `GET`,
  `POST`, `query_params`, `path_params`, `form`, `values`, or `request`.
  Covers `req.query.url`, `request.nextUrl`, `ctx.request.body`.
- Destructuring `const { ... } = <req-like>.<member>` where the member is
  `query`, `body`, `params`, `nextUrl`, `searchParams`, or `formData`:
  every destructured binding is a source. Covers
  `const { url } = req.query`.
- Destructuring `const { url } = <obj>` (also `let`, `var`, and bare
  assignment) where the destructured field name is URL-shaped: the binding
  is a source from any object, not just request members. Covers
  `const { url } = payload`.

## Sinks: outbound request calls

A sink is a call expression whose function position matches one of the
shapes below. The finding line is the sink call.

### Python

- Module-level calls: `requests.<method>(...)`, `httpx.<method>(...)`,
  `aiohttp.<method>(...)`, `urllib.request.<method>(...)` (any method name,
  including `urlopen`)
- Bare `urlopen(...)` and `urlretrieve(...)` calls (covers
  `from urllib.request import urlopen`)
- Client-object calls `<receiver>.<method>(...)` where the receiver name
  contains `client`, `session`, or `driver` (case-insensitive: `client`,
  `self.session`, `self.driver`, `httpx.AsyncClient()`,
  `aiohttp.ClientSession()`, `self._client`) and the method is one of
  `get`, `post`, `put`, `delete`, `head`, `patch`, `options`, `request`,
  `stream`, `fetch`, `ws_connect`. The `driver` receiver covers Selenium
  and framework web drivers (`self.driver.get(url)`).
- Playwright navigation: `<receiver>.goto(...)` where the receiver name
  contains `page`, `browser`, or `driver`
- Context request clients: `<ctx>.request.<method>(...)` where the method is
  an HTTP verb name (`ctx.request.get` shape)

### TypeScript and JavaScript

- Bare calls named `fetch`, `nodeFetch`, `got`, `axios`, or `request`. The
  `fetch` shape covers both the global and a default `node-fetch` import.
- Method calls `axios.<method>(...)` and `got.<method>(...)` (any method)
- Playwright navigation: `<receiver>.goto(...)` where the receiver name
  contains `page`, `browser`, or `ctx`
- Context request clients: `<ctx>.request.<method>(...)` where the method is
  an HTTP verb name

## Sanitizers: the complete-guard call vocabulary

G0 is suppressed only by a call whose callee name matches the complete-guard
vocabulary. "Complete" means the guard resolves all addresses for the host,
range-checks every resolved address, and connects to the validated address
(pinned connect). Semgrep CE cannot verify that pipeline inside a call, so
the rule recognizes it by name, matching this regular expression:

```text
(?i)((.*[._])?(ssrf|safe_?fetch|safe_?get|safe_?request|assert_?safe|
ensure_?public|require_?public)|.*(public_?url|resolve_?and_?pin|
pinned_?request))[a-z_0-9]*
```

In words: callee names such as `ssrf_guard(...)`, `safe_fetch(...)`,
`safeFetch(...)`, `safe_get(...)`, `assert_safe_url(...)`,
`assertPublicUrl(...)`, `ensure_public_url(...)`, `validate_public_url(...)`,
`resolve_and_pin(...)`, `resolveAndPin(...)`, `pinned_request(...)`, and the
same shapes as methods (`self.assert_public_url(...)`,
`guards.safe_fetch(...)`). The sanitizer is `by-side-effect` with
`focus-metavariable` on the first argument, so it covers both the
return-value form (`checked = validate_public_url(url)`) and the
check-and-throw form (`assert_public_url(target)`).

Everything not in that vocabulary leaves the value tainted. In particular
these do NOT sanitize: `urlparse`, `new URL`, `ipaddress.ip_address`,
`net.isIP`, `is_safe_url`/`isSafeUrl`, `validate_url`, `checkUrl`, string
blocklist helpers, and any other unrecognized name. That is deliberate: a
weak or unrecognized guard must not produce silence. The raw G0 finding
still fires, and the layered site resolution in `classify.py` relabels or
suppresses it.

## Layered site resolution (why weak guards still fire G0)

The taint rules produce raw candidate findings, not verdicts. `classify.py`
resolves each enumerated sink in order: a weak-class finding (G1-G6, G8) at
the same site wins and the G0 finding is suppressed, so a scheme-only site
reports G1 and never double-labels as G0; otherwise a complete-guard probe
hit yields recognized-complete; otherwise an intervening-call probe hit
yields "guard detected, shape unrecognized, manual review"; otherwise the
site is G0. This is why the sanitizer vocabulary above is intentionally
narrow: anything the vocabulary misses must stay tainted so the site can be
classified instead of silently passed.

## Analysis ceiling (what these rules cannot see)

Semgrep CE taint is intra-function. Known blind spots, all documented rather
than papered over:

- Helper-factored guards. A guard that lives in `security.py` or
  `safeFetch.ts` and a sink in the caller do not share a taint path. The
  call to the helper shows up only through the intervening-call probe, so
  the site resolves to unrecognized-guard. Mature codebases will produce
  this verdict often; that is expected, not a miss.
- Helper-factored sinks. `await safeFetch(url)` where `fetch` is called
  inside `safeFetch` produces no sink at all at the entry site. The same
  applies when a recognized tool-entry method delegates to a private
  helper (`_run` calling `self._make_request(url)`, which calls
  `driver.get(url)`): the sink is enumerated but sits outside the entry
  extent, so it lands in the "outside recognized entries" review list
  rather than auto-classifying. Coverage reporting counts entry
  candidates and sinks separately so this cannot read as an empty scan.
- Factory-mounted and session-adapter guards. A complete guard attached
  to a transport object is invisible at the call site: a
  `requests.Session` mounted with an SSRF adapter (linkding's
  `GuardedHTTPAdapter` resolves, range-checks, and connects per redirect
  hop), or a session built by a guard factory (crewAI's
  `safe_requests`/adapter pattern), makes `http_client.get(url)` look
  unguarded to lexical analysis. The deterministic class still fires at
  the call site. Do not treat those hits as unguarded; they are the
  ceiling this analyzer cannot see past, the same shape the corpus's
  `g8-crewai-ssrf-adapter-escape-hatch` instance documents.
- Parameter stickiness. A source parameter stays tainted for the whole
  function body: reassigning it (`url = "literal"`) or check-and-throwing on
  it directly (`assert_public_url(url)` then `requests.get(url)`) does not
  clear the taint. The raw G0 finding fires; the complete-guard site probe
  resolves the site to recognized-complete at classify time. Locals derived
  from the parameter (`target = url`) CAN be cleaned by the check-and-throw
  sanitizer.
- Name-based complete-guard recognition is lexical. A callee name that
  collides with the vocabulary without being a full guard (for example a
  formatter named `public_url`, or a `safe_fetch` that skips range checks)
  produces a false negative.
- Unlisted shapes are blind spots, not findings: entry points registered through
  entry-point lists whose callbacks take differently named parameters (the
  dispatch-method source requires an `args`-style parameter name), and
  network clients not in the sink list (raw `http.request` in Node,
  `urllib3` directly, `urllib.request.OpenerDirector`), are counted by the
  coverage summary, not reported as guarded or unguarded.

## Fixture contract

`semgrep test` treats the co-located fixture files as the executable form of
this matrix:

- `rules/python/g0-unguarded-fetch.py`
- `rules/typescript/g0-unguarded-fetch.ts`
- `rules/typescript/g0-unguarded-fetch.js`

Positive cases (annotated to fire): unguarded sinks in every source shape,
a `urlparse`-only and scheme-only path (the incumbent registry rule's false
negative is our true positive), unrecognized helper guards, and the
parameter-stickiness ceiling case. Negative cases (annotated quiet):
recognized complete-guard calls in both forms, hardcoded literal URLs, and
sinks outside any recognized entry point. `tests/fixtures/g0/` holds small
synthetic repos with the same shapes for CLI-level tests.
