---
title: "Rewrite args-flag leak before set (CVE-2026-42945)"
description: "Detects a rewrite directive with '?' in its replacement followed by a set directive referencing a numeric capture group — the exact pattern that triggers the CVE-2026-42945 heap buffer overflow on unpatched nginx."
---

# [unnamed_groups] Rewrite `?` leaks args-flag to subsequent `set $N` (CVE-2026-42945)

CVE-2026-42945 is a remote code execution vulnerability affecting nginx. In certain rewrite configurations on unpatched versions, an unauthenticated attacker can trigger a heap buffer overflow in a nginx worker process by sending a crafted HTTP request.

## What this check looks for

This plugin flags a `rewrite` directive where both of the following are true within the same scope (the same block, or across `if`/`include`/`map`/`geo` boundaries that do not introduce a new context):

1. The replacement string contains `?` (which activates nginx's args-escaping flag on the script engine)
2. A subsequent `set` directive references a numeric capture group (`$1`, `$2`, …)

Because Gixy-Next cannot determine the nginx version from the configuration, any matching pattern is reported as **INFORMATION** rather than a warning — if you are already on a patched version, no action is required.

## Why this is a problem

CVE-2026-42945 is a bug in nginx itself — a heap buffer overflow in the rewrite script engine. The only real fix is upgrading nginx. This plugin detects the configuration shape that would be vulnerable on an unpatched server.

The `?` in a rewrite replacement tells nginx to treat everything after it as query-string arguments, which requires URL-encoding special characters. On unpatched nginx, that "I am in query-string mode" flag is not cleared when the rewrite finishes. A subsequent `set $var $N` then allocates a buffer sized for the raw (unencoded) value, but writes the URL-encoded version — which can be several times longer — overflowing the buffer.

Note that the `?` does not need to be in the same `rewrite` as any `$N` reference — the canonical trigger has no capture reference in the rewrite replacement at all:

```nginx
location / {
    rewrite ^(.*) /new?c=1;   # just needs a ?
    set $myvar $1;            # overflow here on unpatched nginx
    return 200 $myvar;
}
```

## Fix and workaround

Upgrade to nginx 1.30.1+ (stable) or 1.31.0+ (mainline) — this is the real fix.

If you cannot upgrade immediately, replacing numeric captures with named captures (`(?<name>...)`) removes the vulnerable pattern from your configuration and is a valid temporary workaround. Named captures are also simply easier to read and maintain — a `$uid` is clearer than a `$1` whose meaning depends on counting parentheses.

## Bad configuration

```nginx
location / {
    rewrite ^(.*) /new?c=1;
    set $myvar $1;
}
```

```nginx
location / {
    rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2;
    set $extra $2;
}
```

## Better configuration

Replace numeric captures with named captures so that no `set` directive references `$1`, `$2`, etc.:

```nginx
location / {
    rewrite ^(?<path>.*) /new?c=1;
    set $myvar $path;
}
```

```nginx
location / {
    rewrite ^/users/(?<uid>[0-9]+)/profile/(?<tab>.*)$ /profile.php?id=$uid&tab=$tab last;
}
```

## Additional notes

- A `set $var $N` that appears **before** the `rewrite` in the same block is not flagged — `is_args` is only set after the `rewrite` runs, so earlier `set` directives are not affected.
- A `rewrite` with no `?` in its replacement never sets `is_args` and is not flagged, even if it is followed by `set $var $N`.
- Affected versions: NGINX Open Source 0.6.27–1.30.0 (fixed in 1.30.1/1.31.0), NGINX Plus R32–R36 (fixed in R32 P6 / R36 P4).
- For more information see [CVE-2026-42945 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-42945).
