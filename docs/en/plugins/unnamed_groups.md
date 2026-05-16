---
title: "Unnamed capture groups in rewrite with query string"
description: "Detects rewrite directives that use numeric capture group references ($1, $2, …) in a replacement URL that also contains a query string — the pattern associated with CVE-2026-42945."
---

# [unnamed_groups] Unnamed capture groups in rewrite with query string

## What this check looks for

This plugin flags a specific pattern associated with CVE-2026-42945: a `rewrite` directive whose replacement URL contains a `?` **and** references numeric capture groups (`$1`, `$2`, …) anywhere in that replacement. Not all uses of unnamed capture groups are flagged — only this combination.

## Why this is a problem

CVE-2026-42945 ("nginx rift") is a bug in nginx itself. The only real fix is to update nginx to a patched version. If you are already running a patched version (NGINX Open Source 1.30.1+ or 1.31.0+, or NGINX Plus R32 P6+ / R36 P4+), **no action is required** — this finding does not apply to you.

Because Gixy-Next cannot determine the nginx version from the config alone, any matching pattern is reported as **INFORMATION** rather than a warning.

On unpatched versions, switching to named capture groups avoids the vulnerable pattern. Named groups are also worth adopting regardless: `$id` and `$tab` are self-documenting in a way that `$1` and `$2` are not.

## Bad configuration

```nginx
# $1 and $2 in the query string
rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2 last;

# $1 in the path — also flagged when ? is present anywhere in the replacement
rewrite ^/(.*)$ /$1?v=2 last;
```

## Better configuration

```nginx
rewrite ^/users/(?<id>[0-9]+)/profile/(?<tab>.*)$ /profile.php?id=$id&tab=$tab last;

rewrite ^/(?<path>.*)$ /$path?v=2 last;
```

## Additional notes

- Rewrites with no `?` in the replacement are not flagged, even if they use positional captures.
- Named capture group references (`$id`, `$path`, etc.) and nginx built-in variables (`$arg_id`, etc.) are not flagged.
- If nginx is already patched, this finding requires no action — it is reported as INFORMATION precisely because vulnerability depends on the nginx version.
- Affected (unpatched) versions: NGINX Open Source 0.6.27–1.30.0, NGINX Plus R32–R36.
- For more information see [CVE-2026-42945 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-42945).
