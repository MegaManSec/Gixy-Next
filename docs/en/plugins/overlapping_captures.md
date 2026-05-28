---
title: "Rewrite with overlapping captures in redirect/args context (CVE-2026-9256)"
description: "Detects a rewrite directive whose regex contains nested captures and whose replacement references multiple of those captures by $N in redirect or arguments context — the pattern that triggers CVE-2026-9256 on unpatched nginx."
---

# [overlapping_captures] Rewrite overlapping captures overflow buffer in redirect/args context (CVE-2026-9256)

CVE-2026-9256 (nicknamed "nginx-poolslip") is a remote code execution vulnerability affecting nginx. In certain rewrite configurations on unpatched versions, an unauthenticated attacker can trigger a heap buffer overflow in a nginx worker process by sending a crafted HTTP request.

## What this check looks for

This plugin flags a `rewrite` directive where all of the following are true:

1. The regex has two captures (named or unnamed) where one is nested inside the other, for example `^/((.*))$` or `^/(?<outer>(.*))$`, and the replacement references both by `$N` (with neither `$N` repeated).
2. The replacement contains no nginx variables other than the `$N` references (no `$host`, `${uri}`, etc.).
3. The captures end up URI-escaped on output — any of:
    - an explicit `redirect` or `permanent` flag,
    - the replacement starts with `http://` or `https://` (implicit redirect), or
    - the replacement contains a `?` (other than a sole trailing one, which nginx strips) and at least two of the referenced `$N` appear after it.

Because Gixy-Next cannot determine the nginx version from the configuration, any matching pattern is reported as **INFORMATION** rather than a warning — if you are already on a patched version, no action is required.

## Why this is a problem

On unpatched nginx, a replacement with no variables and no duplicate `$N` makes the worker pre-compute the output buffer size from the regex captures and the URI, but the formula only counts the URI's escape size once. With overlapping captures, two `$N` references can match the same input bytes, so the captures together are longer than the URI and the URI-based escape budget is too small.

In redirect or arguments context each capture is URI-escaped on write (each `+` becomes `%2B`, each space becomes `%20`, etc.), so the actual output can be several times the planned buffer. A crafted request like `/++++++++++++++++++++++++++++++` against `rewrite ^/((.*))$ http://x/$1$2 redirect;` overruns the worker's heap.

## Fix and workaround

Upgrade to nginx 1.30.2+ (stable) or 1.31.1+ (mainline).

If you cannot upgrade immediately, remove the `$N` references from the replacement: convert the captures to named ones (`(?<name>...)`) and reference them by `$name` rather than `$N`. PCRE numbers named captures alongside unnamed ones, so `$1` still works for `(?<name>...)` — renaming the regex group alone is not enough.

## Bad configurations

Explicit `redirect` flag:

```nginx
location / {
    rewrite ^/((.*))$ http://127.0.0.1:8080/$1$2 redirect;
}
```

Implicit redirect from the `http://` prefix, no flag needed:

```nginx
location / {
    rewrite ^/((.*))$ http://127.0.0.1:8080/$1$2;
}
```

`?` in the replacement:

```nginx
location / {
    rewrite ^/((.*))$ http://127.0.0.1:8080/?$1$2;
}
```

Named outer capture still triggers the bug if both captures are referenced by `$N`:

```nginx
location / {
    rewrite ^/(?<outer>(.*))$ http://example.com/$1$2 redirect;
}
```

## Better configuration

```nginx
location / {
    rewrite ^/(?<path>.*)$ http://127.0.0.1:8080/$path redirect;
}
```

## Additional notes

- Sibling captures alone (`(.*)/(.*)`) are fine — they cover non-overlapping parts of the input.
- Cross-pair `$N` references like `^/((.*))/((.*))$ /foo/$1$3` are fine — `$1` and `$3` are siblings even though each pair is nested.
- A replacement that references only one `$N` is fine — the bug needs at least two.
- A replacement containing any nginx variable, or repeating the same `$N`, takes a different length-calc path and is fine.
- A `?` only at the end of the replacement is stripped by nginx and does not trigger the args path.
- Affected versions: NGINX Open Source 0.1.17–1.30.1 and 1.31.0 (fixed in 1.30.2/1.31.1), NGINX Plus R32–R36 (fixed in R32 P7 / R36 P5), NGINX Plus R37 (fixed in R37.0.1.1).
- For more information see [CVE-2026-9256 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-9256).
