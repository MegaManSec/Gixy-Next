---
title: "Unnamed capture groups in rewrite with query string"
description: "Detects rewrite directives that combine a '?' in the replacement URL with numeric capture group references ($1, $2, …) — the pattern exploited by CVE-2026-42945 ('nginx rift')."
---

# [unnamed_groups] Unnamed capture groups in rewrite with query string

## What this check looks for

This plugin flags `rewrite` directives where the replacement URL contains a `?` **and** any numeric capture group reference (`$1`, `$2`, …) appears anywhere in that replacement — before or after the `?`.

## Why this is a problem

CVE-2026-42945 ("nginx rift") is a heap buffer overflow in `ngx_http_rewrite_module`. The bug arises from a two-pass mismatch: the buffer length is calculated using the raw (unescaped) size of capture group values, but the copy applies `NGX_ESCAPE_ARGS` escaping — which is triggered by the presence of `?` anywhere in the replacement string. Characters like `%`, `+`, and `&` in attacker-controlled values expand from 1 to 3 bytes, overflowing the buffer. The overflow affects **all** `$N` references in the replacement, including those that appear before the `?`.

## Why this is informational

Whether a given deployment is actually exploitable depends entirely on the nginx version and whether the relevant patch has been applied — information that is not present in a config file. Gixy-Next therefore reports this at **INFORMATION** severity rather than as a confirmed vulnerability.

The recommended fix — switching from positional (`$1`, `$2`) to named capture groups — also improves readability. This benefit applies regardless of nginx version.

## Bad configuration

`$N` in the query string (the obvious case):

```nginx
rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2 last;
```

`$N` in the path portion — also vulnerable because `?` is present in the replacement:

```nginx
rewrite ^/(.*)$ /$1?v=2 last;
```

## Better configuration

Use named capture groups and reference them by name:

```nginx
rewrite ^/users/(?<id>[0-9]+)/profile/(?<tab>.*)$ /profile.php?id=$id&tab=$tab last;
```

```nginx
rewrite ^/(?<path>.*)$ /$path?v=2 last;
```

## Additional notes

- The trigger is the presence of `?` in the replacement. Without `?`, positional references are safe even with the same regex.
- Named capture group references (e.g., `$id`, `$path`) do not go through the vulnerable code path and are not flagged.
- Nginx built-in variables such as `$arg_id` are not positional capture references and are not flagged.
- Affected versions: NGINX Open Source 0.6.27–1.30.0 (fixed in 1.30.1/1.31.0), NGINX Plus R32–R36.
- For more information see [CVE-2026-42945 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-42945).
