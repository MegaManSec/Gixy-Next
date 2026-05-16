---
title: "Unnamed capture groups in rewrite with query string"
description: "Detects rewrite directives that use numeric capture group references ($1, $2, …) in a replacement URL that also contains a query string — the pattern associated with CVE-2026-42945."
---

# [unnamed_groups] Unnamed capture groups in rewrite with query string

## What this check looks for

This plugin flags `rewrite` directives where the replacement URL contains a `?` and also references positional capture groups (`$1`, `$2`, …) anywhere in that replacement — before or after the `?`.

## Why this is a problem

CVE-2026-42945 ("nginx rift") is a bug in nginx itself. The only real fix is to update nginx to a patched version. Whether a given deployment is vulnerable depends on the nginx version — Gixy-Next cannot determine this from the config alone, so this is reported as **INFORMATION**.

Switching to named capture groups avoids the vulnerable pattern on unpatched versions and is worth doing regardless: `$id` and `$tab` are self-documenting in a way that `$1` and `$2` are not, making rewrites easier to understand and maintain.

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
- Affected versions: NGINX Open Source 0.6.27–1.30.0 (fixed in 1.30.1/1.31.0), NGINX Plus R32–R36.
- For more information see [CVE-2026-42945 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-42945).
