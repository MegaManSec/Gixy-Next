---
title: "Rewrite args-flag leak before set or if (CVE-2026-42945)"
description: "Detects a rewrite directive with '?' in its replacement followed by a set or if directive that reads a numeric capture group — the pattern that triggers CVE-2026-42945 on unpatched nginx."
---

# [unnamed_groups] Rewrite `?` leaks args-flag to subsequent `set $N` / `if … $N …` (CVE-2026-42945)

CVE-2026-42945 is a remote code execution vulnerability affecting nginx. In certain rewrite configurations on unpatched versions, an unauthenticated attacker can trigger a heap buffer overflow in a nginx worker process by sending a crafted HTTP request.

## What this check looks for

This plugin flags a `rewrite` directive where all of the following are true within the same scope (the same block, or across `if` / `include` / `map` / `geo` boundaries that do not introduce a new context):

1. The replacement contains `?`, and the rewrite does not itself terminate the rewrite phase: it has no `last`, `break`, `redirect`, or `permanent` flag, and its replacement does not start with `http://`, `https://`, or `$scheme`.
2. A later directive in the same scope reads a numeric capture group (`$1`, `$2`, …) in one of these forms:
    * `set $var VALUE`
    * `if ($var = VALUE)` or `if ($var != VALUE)`
    * `if (-f VALUE)` (or `-d`, `-e`, `-x`, with optional `!`)
3. There is no `return` or standalone `break;` between the rewrite and that directive.

Because Gixy-Next cannot determine the nginx version from the configuration, any matching pattern is reported as **INFORMATION** rather than a warning — if you are already on a patched version, no action is required.

## Why this is a problem

The `?` in a rewrite replacement puts nginx into "query-string mode", which URL-encodes special characters on output. On unpatched nginx that mode is not cleared when the rewrite finishes, so a subsequent `set` or `if` that reads a numeric capture allocates a buffer for the raw value but writes the URL-encoded value — which can be several times longer — overflowing the buffer.

The `?` does not need to be in the same `rewrite` as any `$N` reference. The canonical trigger has no capture reference in the rewrite replacement at all:

```nginx
location / {
    rewrite ^(.*) /new?c=1;   # just needs a ?
    set $myvar $1;            # overflow here on unpatched nginx
    return 200 $myvar;
}
```

## Fix and workaround

Upgrade to nginx 1.30.1+ (stable) or 1.31.0+ (mainline).

If you cannot upgrade immediately, remove the `$N` reference from the affected `set` or `if`: convert the regex's unnamed capture to a named one (`(?<name>...)`) and reference it by `$name`. PCRE numbers named captures alongside unnamed ones, so `$1` still works for `(?<name>...)` — renaming the regex group alone is not enough.

## Bad configurations

```nginx
location / {
    rewrite ^(.*) /new?c=1;
    set $myvar $1;
}
```

```nginx
location / {
    rewrite ^(.*) /new?c=1;
    if ($host = "$1") { return 200 ok; }
}
```

```nginx
location / {
    rewrite ^(.*) /new?c=1;
    if (-f "/srv/$1") { return 200 ok; }
}
```

## Better configuration

```nginx
location / {
    rewrite ^(?<path>.*) /new?c=1;
    set $myvar $path;
}
```

## Additional notes

- A `set $var $N` *before* the `rewrite` in the same block is fine — the args flag is only set when the `rewrite` runs.
- A `rewrite` with no `?` in its replacement is fine.
- A `rewrite` with a terminating flag (`last`, `break`, `redirect`, `permanent`) or an `http://` / `https://` / `$scheme` prefix on its replacement is fine — it halts the engine on match, so any later `set` or `if` does not run.
- A `return` or standalone `break;` between the rewrite and the `set` or `if` is fine — it halts the engine before the vulnerable directive runs.
- `if ($var ~ "regex")` is fine — the `~` operator does not allocate a buffer from the pattern.
- `if ($var)` (truthy test) is fine — it is just a variable lookup.
- `return 200 $N` is fine — `return` uses a separate engine.
- Affected versions: NGINX Open Source 0.6.27–1.30.0 (fixed in 1.30.1/1.31.0), NGINX Plus R32–R36 (fixed in R32 P6 / R36 P4).
- For more information see [CVE-2026-42945 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-42945).
