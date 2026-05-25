---
title: "Rewrite args-flag leak before set or if (CVE-2026-42945)"
description: "Detects a rewrite directive with '?' in its replacement followed by a set or if directive that reads a numeric capture group. This is the pattern that triggers CVE-2026-42945 on unpatched nginx."
---

# [unnamed_groups] Rewrite `?` leaks args-flag to a subsequent `set` or `if` (CVE-2026-42945)

CVE-2026-42945 is a remote code execution vulnerability affecting nginx. In certain rewrite configurations on unpatched versions, an unauthenticated attacker can trigger a heap buffer overflow in a nginx worker process by sending a crafted HTTP request.

## What this check looks for

This plugin flags a `rewrite` directive where both of the following are true within the same scope (the same block, or across `if`, `include`, `map`, or `geo` boundaries that do not introduce a new context):

1. The replacement string contains `?` (which activates nginx's args-escaping flag on the script engine).
2. A subsequent directive references a numeric capture group (`$1`, `$2`, ...) via `set $var ...`, `if ($var = ...)`, `if ($var != ...)`, or `if (-f ...)` (the `-d`, `-e`, `-x`, and negated file-test operators are treated identically).

Because Gixy-Next cannot determine the nginx version from the configuration, any matching pattern is reported as **INFORMATION** rather than a warning — if you are already on a patched version, no action is required.

## Why this is a problem

The `?` in a rewrite replacement tells nginx to treat everything after it as query-string arguments, which requires URL-encoding special characters. On unpatched nginx, that "query-string mode" flag is not cleared when the rewrite finishes. A subsequent `set` or `if` that reads a numeric capture then allocates a buffer sized for the raw value but writes the URL-encoded version (which can be several times longer), overflowing the buffer.

The `?` does not need to be in the same `rewrite` as the `$N` reference. The canonical trigger has no capture reference in the rewrite replacement at all:

```nginx
location / {
    rewrite ^(.*) /new?c=1;   # just needs a ?
    set $myvar $1;            # overflow here on unpatched nginx
    return 200 $myvar;
}
```

## Fix and workaround

Upgrade to nginx 1.30.1+ (stable) or 1.31.0+ (mainline).

If you cannot upgrade immediately, remove the `$N` reference from the affected `set` or `if`. Converting the regex's unnamed group to a named capture (`(?<name>...)`) and updating the consumer to read `$name` works. Note that simply naming the group is not sufficient on its own: PCRE numbers named groups alongside unnamed ones, so `$1` continues to work for `(?<name>...)`. The directive that reads the capture must also be updated.

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

The plugin deliberately does not flag the following shapes:

- A `set $var $N` that appears *before* the `rewrite` in the same block. The args flag is only set when the `rewrite` actually runs, so earlier `set` directives are unaffected.
- A `rewrite` that terminates the rewrite phase on its own. This covers the `last`, `break`, `redirect`, and `permanent` flags, as well as replacements that start with `http://`, `https://`, or `$scheme` (which nginx treats as implicit redirects). When the `rewrite` matches, the engine halts and any later `set` or `if` does not run.
- A `return` or standalone `break;` directive sitting between the `rewrite` and the consumer. Both unconditionally halt the engine before the vulnerable directive can execute.
- `if ($var ~ "regex")` (a regex-match condition) and `if ($var)` (a truthy test). Neither goes through the same code path as the vulnerable equality and file-test forms.
- `return 200 $N`. The `return` directive uses a separate script engine that is not affected.

Affected versions: NGINX Open Source 0.6.27 through 1.30.0 (fixed in 1.30.1 and 1.31.0), and NGINX Plus R32 through R36 (fixed in R32 P6 and R36 P4).

For more information see [CVE-2026-42945 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-42945).
