---
title: "Unnamed capture groups in rewrite query string"
description: "Detects rewrite directives that reference numeric capture groups ($1, $2, …) in the query-string portion of the replacement URL — the pattern associated with CVE-2026-42945 ('nginx rift')."
---

# [unnamed_groups] Unnamed capture groups in rewrite query string

## What this check looks for

This plugin flags `rewrite` directives where numeric capture group references (`$1`, `$2`, …) appear **after the `?`** in the replacement URL — the specific pattern associated with CVE-2026-42945.

## Why this is informational

CVE-2026-42945 ("nginx rift") is a vulnerability in nginx itself, not in the configuration. Whether a given deployment is actually exploitable depends entirely on the nginx version and whether the relevant patch has been applied — information that is not present in a config file. Gixy-Next therefore reports this at **INFORMATION** severity rather than as a confirmed vulnerability.

The recommended fix — switching from positional (`$1`, `$2`) to named capture groups — also improves readability by making the purpose of each substitution explicit. This benefit applies regardless of nginx version.

## Bad configuration

```nginx
server {
    location / {
        rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2 last;
    }
}
```

`$1` and `$2` are positional references to unnamed capture groups. When they appear in the query string portion of the replacement URL this matches the CVE-2026-42945 pattern.

## Better configuration

Use named capture groups and reference them by name:

```nginx
server {
    location / {
        rewrite ^/users/(?<id>[0-9]+)/profile/(?<tab>.*)$ /profile.php?id=$id&tab=$tab last;
    }
}
```

This eliminates the CVE-2026-42945 pattern entirely and makes the intent of each substitution self-documenting.

## Additional notes

- Only references appearing **after the `?`** in the replacement URL are flagged. Positional references in the path portion (before `?`) are not part of the CVE pattern and are not reported.
- Variables that contain digits but are not positional capture group references (e.g., `$arg_id`, `$http2_push`) are not flagged.
- For more information see [CVE-2026-42945 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-42945).
