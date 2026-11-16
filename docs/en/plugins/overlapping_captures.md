---
title: "Overlapping Rewrite Captures (CVE-2026-9256)"
description: "Detects a rewrite whose replacement escapes two overlapping captures by $N, which overflows a heap buffer on NGINX before 1.30.2 and 1.31.1 (CVE-2026-9256)."
---

# [overlapping_captures] Overlapping captures in a `rewrite` redirect or query string (CVE-2026-9256)

## What this check looks for

A `rewrite` whose replacement has no variables and no repeated `$N`, and references two captures that can cover the same bytes:

- one nested in the other, such as `^/((.*))$` or `^/(?<outer>(.*))$`,
- one in a positive lookahead and the other after it, such as `^/(?=(.*))(.*)$`,
- one in a positive lookbehind and the other before it, such as `^/(.*)(?<=(.))$`.

The captures must be escaped on output: a `redirect` or `permanent` flag, an `http://` or `https://` replacement, or both `$N` after a `?` (a sole trailing `?` does not count). Findings are INFORMATION, because Gixy-Next cannot tell the NGINX version.

## Why this is a problem

On NGINX before 1.30.2 and 1.31.1, such a replacement is sized with room to escape the URI once, but overlapping captures escape the same bytes twice. A request such as `/++++++++` then overflows the heap.

## Bad configuration

Nested captures in a redirect:

```nginx
location / {
    rewrite ^/((.*))$ http://127.0.0.1:8080/$1$2 redirect;
}
```

Lookahead and following capture, both after `?`:

```nginx
location / {
    rewrite ^/(?=(.*))(.*)$ /p?a=$1&b=$2;
}
```

## Better configuration

Upgrade NGINX. Until then, reference named captures instead of `$N`. Naming the groups is not enough on its own, because PCRE still numbers them.

```nginx
location / {
    rewrite ^/(?<path>.*)$ http://127.0.0.1:8080/$path redirect;
}
```

## Additional notes

- Not reported: sibling captures such as `(.*)/(.*)` or `$1$3` in `^/((.*))/((.*))$`, `$1$2` in `^/(.)(?=(.*))(.*)$` since `$1` ends before the lookahead, captures in negative lookarounds, a single `$N`, and a replacement with a variable or a repeated `$N`.
- Affected: NGINX Open Source 0.1.17 to 1.30.1 and 1.31.0 (fixed in 1.30.2 and 1.31.1), and NGINX Plus R32 to R36 (fixed in R32 P7 and R36 P5) and R37 (fixed in R37.0.1.1). See [CVE-2026-9256 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-9256).
