---
title: "Rewrite with overlapping captures in redirect/args context (CVE-2026-9256)"
description: "Detects a rewrite directive whose regex contains nested captures and whose replacement references multiple of those captures by $N in redirect or arguments context — the exact pattern that triggers the CVE-2026-9256 heap buffer overflow on unpatched nginx."
---

# [overlapping_captures] Rewrite overlapping captures overflow buffer in redirect/args context (CVE-2026-9256)

CVE-2026-9256 (nicknamed "nginx-poolslip") is a remote code execution vulnerability affecting nginx. In certain rewrite configurations on unpatched versions, an unauthenticated attacker can trigger a heap buffer overflow in a nginx worker process by sending a crafted HTTP request.

## What this check looks for

This plugin flags a `rewrite` directive where all of the following are true:

1. The regex contains **overlapping (nested) captures** — one capturing group (named *or* unnamed) is contained inside another, e.g. `^/((.*))$` or `^/(?<outer>(.*))$`
2. The replacement string references **two or more distinct numeric captures** (`$1`, `$2`, …), with no `$N` repeated
3. The replacement contains **no nginx variables** (no `$host`, `${uri}`, etc. — only literal text and `$N` refs)
4. The rewrite runs in redirect or arguments context — *any* of:
    * the replacement starts with `http://` or `https://` (an implicit redirect)
    * the rewrite uses the explicit `redirect` or `permanent` flag
    * the replacement contains a `?` (other than a sole trailing one, which nginx strips) *and* at least two of the referenced `$N` appear after that `?`
5. The pair of `$N` captures actually overlap — one referenced capture is a syntactic ancestor of another. Sibling captures (e.g. `((.*))/((.*))` referenced as `$1$3`) are not reported.

Because Gixy-Next cannot determine the nginx version from the configuration, any matching pattern is reported as **INFORMATION** rather than a warning — if you are already on a patched version, no action is required.

## Why this is a problem

CVE-2026-9256 is a bug in nginx itself — a heap buffer overflow in `ngx_http_script_regex_start_code`. The only real fix is upgrading nginx. This plugin detects the configuration shape that would be vulnerable on an unpatched server.

When the replacement has no nginx variables and no duplicate `$N` refs, nginx pre-computes the output buffer size from the regex captures alone. The buggy formula adds each capture's raw byte length once and adds the URI's escape size once. With overlapping captures, two `$N` references can match the same input bytes — the captures together are longer than the URI, but the URI-based escape calc never accounts for that. In redirect or arguments context the captures are URI-escaped on output (each `+` becomes `%2B`, each space becomes `%20`, etc.), and the actual written bytes can be several times the planned buffer. A crafted request like `/++++++++++++++++++++++++++++++` against `rewrite ^/((.*))$ http://x/$1$2 redirect;` overruns the worker's heap.

A replacement that contains any nginx variable, or that references the same `$N` more than once, takes an entirely different length-calc code path that pre-computes per-request output size, so this CVE does not apply.

## Fix and workaround

Upgrade to nginx 1.30.2+ (stable) or 1.31.1+ (mainline) — this is the real fix.

If you cannot upgrade immediately, the workaround is to **remove the `$N` references from the replacement**: convert the captures to named ones (`(?<name>...)`) **and** reference them by `$name` rather than `$N`. PCRE numbers named captures alongside unnamed ones, so `$1` still works for `(?<name>...)` — switching only the regex syntax leaves the vulnerable code path. Named captures referenced by name are also simply easier to read and maintain.

## Bad configurations

Explicit `redirect` flag with nested unnamed captures:

```nginx
location / {
    rewrite ^/((.*))$ http://127.0.0.1:8080/$1$2 redirect;
}
```

Implicit redirect from the `http://` prefix — no flag needed:

```nginx
location / {
    rewrite ^/((.*))$ http://127.0.0.1:8080/$1$2;
}
```

Args context from a `?` in the replacement:

```nginx
location / {
    rewrite ^/((.*))$ http://127.0.0.1:8080/?$1$2;
}
```

Named outer capture still produces overlapping `$N` refs:

```nginx
location / {
    rewrite ^/(?<outer>(.*))$ http://example.com/$1$2 redirect;
}
```

## Better configuration

Replace unnamed captures with named captures **and** stop referencing them by `$N`:

```nginx
location / {
    rewrite ^/(?<path>.*)$ http://127.0.0.1:8080/$path redirect;
}
```

```nginx
location / {
    rewrite ^/(?<prefix>[^/]+)/(?<rest>.*)$ http://127.0.0.1:8080/?p=$prefix&r=$rest;
}
```

## Additional notes

- A `rewrite` whose regex contains only **sibling** captures (`(.*)/(.*)`) is not flagged — the captures cover non-overlapping parts of the input and the buggy length calc is not undersized.
- A `rewrite` whose replacement references only **one** `$N` is not flagged — the bug requires multiple distinct capture references.
- A `rewrite` whose replacement contains any nginx variable is not flagged — variables trigger a different length-calc path that was not affected.
- A `rewrite` that references the same `$N` more than once is not flagged — duplicate refs also trigger the safe length-calc path.
- A `rewrite` without `?`, without a `redirect`/`permanent` flag, and without an `http://`/`https://` prefix on its replacement is not flagged — none of the captures are URI-escaped on output.
- A sole *trailing* `?` is not flagged on its own — nginx strips it (it means "drop the original arguments") before compiling the replacement.
- Affected versions: NGINX Open Source 0.1.17–1.30.1 and 1.31.0 (fixed in 1.30.2/1.31.1), NGINX Plus R32–R36 (fixed in R32 P7 / R36 P5), NGINX Plus R37 (fixed in R37.0.1.1).
- For more information see [CVE-2026-9256 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-9256).
