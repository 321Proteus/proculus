# Signatures

Signatures say how to recognise a technology, product, admin panel or
environment from what a web service shows. They only ever **look**: a signature
can test a header, a cookie name, the page title or body, the favicon hash, the
TLS certificate, and a few fixed extra pages (`/login`, `/admin`, `/version`...)
fetched with a plain GET. It cannot send parameters, log in or change anything.

125 signatures are built in (servers, frameworks, CMS, admin panels, IoT,
staging/debug exposure, TLS/header/cookie hygiene). You can add your own, replace
built-in ones or switch them off, without rebuilding anything.

```sh
signatures list --category cms
signatures lint my-signatures/            # check them, and run their examples
http-prober --signatures my-signatures/ --scope ... --allowed-ports ... http://10.0.0.5
```

A complete, tested example is in [`examples/custom.json`](examples/custom.json).

## File format

A JSON file with a list of signatures (a directory of such files works too):

```json
{
  "format": 1,
  "disable": ["server-version-disclosure"],
  "signatures": [ { ... } ]
}
```

| key | meaning |
|---|---|
| `id` | required; lowercase letters, digits, `.` `_` `-`; unique |
| `name` | required; shown in reports |
| `category` | required: `cms`, `framework`, `server`, `iot`, `staging`, `admin`, `other` |
| `signals` | required; the evidence, see below |
| `threshold` | confidence needed to report (0 to 1, default 0.5) |
| `interest` | 0-5: how much an analyst should care that this is present (default 0) |
| `tags`, `description`, `references` | optional |
| `exclude` | a condition; if it matches, the signature does not apply |
| `version` | `{ "field": ..., "regex": "nginx/([0-9.]+)" }`: one capture group gives the version |
| `examples` | strongly recommended: see Testing |
| `override` | `true` to replace a built-in signature with the same id |
| `enabled` | `false` to define a signature but keep it off |

`disable` (top level) lists ids, usually built-in ones, to switch off.

### Signals and confidence

Each signal has a `weight` (how strongly it alone suggests the technology) and a
`match` condition. Matched signals combine as `1 - (1-w1)(1-w2)...`, capped at
0.99, so independent weak hints add up while one strong hint is enough alone:
a header worth 0.9 gives 90%; add a cookie worth 0.5 and it becomes 95%.
The signature is reported when the result reaches its `threshold`. Mark a
signal `"required": true` if the signature must not be reported without it.
A signature whose signals can never reach its threshold is rejected.

Rough guide: 0.9+ for something only this product emits (a specific header or
cookie name), 0.5-0.7 for a characteristic path or HTML fragment, 0.2-0.4 for
generic hints.

### Conditions

A condition is a matcher, or `all` / `any` / `not` around other conditions
(at most 8 levels deep):

```json
{ "field": "header:x-powered-by", "op": "contains", "value": "PHP/" }
{ "all": [ { ... }, { ... } ] }
{ "any": [ { ... }, { ... } ] }
{ "not": { ... } }
```

Operators: `equals`, `contains`, `prefix`, `suffix`, `regex`, `exists`,
and `gt`, `ge`, `lt`, `le` for numbers. `value` may be a list: any of them
matches. String matching ignores case unless `"case_sensitive": true`.
`exists` takes `true` (default) or `false`. A list field matches if any element does.
Regular expressions are PCRE2 under strict match limits, so a bad pattern
cannot hang the scanner; patterns are limited to 500 characters.

### Fields

Run `signatures fields` for the full list. In short:

- numbers: `status`, `port`, `favicon_hash`, `body_length`, `tls.key_bits`
- text: `url`, `title`, `body`, `server`, `content_type`, `host`, `tls.version`,
  `tls.cipher`, `tls.subject`, `tls.issuer`, `tls.key_type`,
  `tls.signature_algorithm`, `service.name`, `service.product`, `service.version`
- yes/no: `tls`, `tls.self_signed`, `tls.expired`, `tls.not_yet_valid`, `tls.hostname_match`
- lists: `cookie`, `cookie_insecure`, `cookie_no_httponly`, `redirect_location`,
  `tls.san`, `hostnames`, `header_names`
- `header:<name>`: values of a response header, name in lowercase
  (`header:server`, `header:x-powered-by`). Use this rather than `server`
  for header matching, as the built-in signatures do.
- `path:<p>:status|body|title|content_type|redirect|header:<name>`: an extra page.

### Extra paths

Using a `path:` field makes the prober fetch that page. This is restricted on
purpose: GET only, absolute path of plain characters (letters, digits, `/ . _ - ~ %`),
no query string, no `..`, at most 200 characters, and at most 20 distinct paths
per file. Paths are fetched only after the main page answered, from the same
site, without following redirects, and at most `--max-paths` (default 8) per
service, most valuable first. `signatures paths` shows the order. Design
signatures so the page *content* confirms the match: many sites answer every
path with the same page (or 200 for anything), so a status code alone is weak.

## Testing

Give each signature `examples`: evidence and what is expected.

```json
{ "name": "login page", "evidence": { "path:/wp-login.php:status": 200, "path:/wp-login.php:body": "wp-submit" } },
{ "name": "plain site", "evidence": { "body": "<html></html>" }, "expect": "no-match" },
{ "name": "version", "evidence": { "header:server": "nginx/1.24.0" }, "version": "1.24.0" }
```

`signatures lint FILE` reports mistakes with their location
(`signals[1].match.field: unknown field "titel"`), warns about signatures
without examples, and fails if an example does not behave as stated.
`signatures match evidence.json` shows what all signatures say about a piece of
evidence; `http-prober --dump-evidence` writes the evidence it matched, so you
can copy a real service's facts into an example.

## Safety limits

Loading never executes anything: files are data. Limits: 2000 signatures per
file, 20 examples per signature, patterns of 500 characters, 20 probe paths per
source. A file with errors is rejected as a whole by the prober (so a typo does
not silently disable your detection); `lint` shows all problems at once.
