---
title: "Rewrite args-flag leak (CVE-2026-42945)"
description: "Detects a rewrite with '?' in its replacement followed by a set, if or rewrite that reads $N, which overflows a heap buffer on nginx before 1.30.1 and 1.31.0 (CVE-2026-42945)."
---

# [unnamed_groups] Rewrite `?` leaks args-flag to a later `set`, `if` or `rewrite` (CVE-2026-42945)

## What this check looks for

A `rewrite` whose replacement contains `?` (a sole trailing `?` does not count), followed in the same rewrite phase by:

- a `set`, `if ($var = ...)`, `if ($var != ...)` or `if (-f ...)` (or another file test) whose value reads `$N`, or
- a `rewrite` that is not a redirect, reads `$N` before its own `?`, and also holds a variable or repeats a `$N`.

The `$N` must be one the most recent regex can set: the first `rewrite`, or a regex `if` or `rewrite` that runs in between. Findings are INFORMATION, because Gixy-Next cannot tell the nginx version.

## Why this is a problem

On nginx before 1.30.1 and 1.31.0, the `?` turns on argument escaping, and it stays on after the `rewrite`. A later directive sizes its buffer for the raw capture but writes it escaped, so a crafted request overflows the heap.

## Bad configuration

```nginx
location / {
    rewrite ^(.*) /new?c=1;
    set $myvar $1;
}
```

```nginx
location / {
    rewrite ^(.*)$ $1?c=1;
    rewrite ^/f/(.*)$ /p/$1$is_args;
}
```

## Better configuration

Upgrade nginx. Until then, read a named capture instead of `$N`. Naming the group is not enough on its own, because PCRE still numbers it.

```nginx
location / {
    rewrite ^(?<path>.*) /new?c=1;
    set $myvar $path;
}
```

## Additional notes

- Not reported: a consumer after a `rewrite` that stops processing on a match (`last`, `break`, `redirect`, `permanent`, or an `http://`, `https://` or `$scheme` replacement), after `return` or `break`, or reading a group the regex does not define. `return 200 $1` is not affected.
- `$N` inside a regex condition such as `if ($var ~ "$1")` is regex text, not a capture.
- Affected: NGINX Open Source 0.6.27 to 1.30.0 (fixed in 1.30.1 and 1.31.0) and NGINX Plus R32 to R36 (fixed in R32 P6 and R36 P4). See [CVE-2026-42945 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-42945).
