---
title: "Rewrite with overlapping captures in redirect/args context (CVE-2026-9256)"
description: "Detects a rewrite directive whose regex contains nested unnamed captures and whose replacement references multiple of those captures by $N in redirect or arguments context — the exact pattern that triggers the CVE-2026-9256 heap buffer overflow on unpatched nginx."
---

# [overlapping_captures] Rewrite overlapping captures overflow buffer in redirect/args context (CVE-2026-9256)

CVE-2026-9256 (nicknamed "nginx-poolslip") is a remote code execution vulnerability affecting nginx. In certain rewrite configurations on unpatched versions, an unauthenticated attacker can trigger a heap buffer overflow in a nginx worker process by sending a crafted HTTP request.

## What this check looks for

This plugin flags a `rewrite` directive where all of the following are true:

1. The regex contains **overlapping (nested) unnamed captures** — one unnamed `(...)` group is contained inside another, e.g. `^/((.*))$`
2. The replacement string references **two or more distinct numeric captures** (`$1`, `$2`, …)
3. The replacement contains **no nginx variables** (no `$host`, `${uri}`, etc. — only literal text and `$N` refs)
4. Either the replacement contains `?`, **or** the rewrite uses the `redirect`/`permanent` flag

Because Gixy-Next cannot determine the nginx version from the configuration, any matching pattern is reported as **INFORMATION** rather than a warning — if you are already on a patched version, no action is required.

## Why this is a problem

CVE-2026-9256 is a bug in nginx itself — a heap buffer overflow in `ngx_http_script_regex_start_code`. The only real fix is upgrading nginx. This plugin detects the configuration shape that would be vulnerable on an unpatched server.

When the replacement has no nginx variables, nginx pre-computes the output buffer size from the regex captures alone. The buggy formula adds each capture's raw byte length once and adds the URI's escape size once. With overlapping captures, two `$N` references can match the same input bytes — the captures together are longer than the URI, but the URI-based escape calc never accounts for that. In redirect or arguments context the captures are URI-escaped on output (each `+` becomes `%2B`, each space becomes `%20`, etc.), and the actual written bytes can be several times the planned buffer. A crafted request like `/++++++++++++++++++++++++++++++` against `rewrite ^/((.*))$ http://x/$1$2 redirect;` overruns the worker's heap.

A replacement that contains any nginx variable takes an entirely different length-calc code path that pre-computes per-request output size, so this CVE does not apply.

## Fix and workaround

Upgrade to nginx 1.30.2+ (stable) or 1.31.1+ (mainline) — this is the real fix.

If you cannot upgrade immediately, replacing unnamed captures with named captures (`(?<name>...)`) removes the vulnerable pattern from your configuration and is a valid temporary workaround. Named captures are also simply easier to read and maintain — a `$path` is clearer than a `$1` whose meaning depends on counting parentheses.

## Bad configuration

```nginx
location / {
    rewrite ^/((.*))$ http://127.0.0.1:8080/$1$2 redirect;
}
```

```nginx
location / {
    rewrite ^/((.*))$ http://127.0.0.1:8080/?$1$2;
}
```

## Better configuration

Replace unnamed captures with named captures so that no `$N` reference appears in the replacement:

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
- A `rewrite` whose replacement references only **one** `$N` is not flagged — the bug requires multiple capture references in the same replacement.
- A `rewrite` whose replacement contains any nginx variable is not flagged — that triggers a different length-calc path that was not affected.
- A `rewrite` without `?` in its replacement and without a `redirect`/`permanent` flag is not flagged — the captures are never URI-escaped on output.
- Affected versions: NGINX Open Source 0.1.17–1.30.1 and 1.31.0 (fixed in 1.30.2/1.31.1), NGINX Plus R32–R36 (fixed in R32 P7 / R36 P5), NGINX Plus R37 (fixed in R37.0.1.1).
- For more information see [CVE-2026-9256 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-9256).
