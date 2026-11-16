---
title: "Referer Check Bypass"
description: "Detects valid_referers entries that accept a Referer an attacker can produce: none, blocked, open regular expressions and trailing wildcards."
---

# [valid_referers] Weak entries in `valid_referers`

## What this check looks for

This plugin warns when `valid_referers` includes:

- the `none` or `blocked` keyword;
- a regular expression (`~...`) that is not anchored with `^`, that does not end the host name, or that leaves part of the host's registrable domain to the client, such as the unescaped dots in `~^www.example.com/`;
- a name with a trailing wildcard, such as `example.*`.

## Why this is a problem

Any page can make the browser leave out the `Referer`, for example with `referrerpolicy="no-referrer"`, and `none` accepts that. `blocked` accepts a `Referer` that does not start with `http://` or `https://`, which browsers rarely send.

NGINX matches a regular expression anywhere in the `Referer` after its scheme. `~\.example\.com` also accepts `https://www.example.com.evil.net/`, and `https://evil.net/www.example.com` when the attacker's page sends its full URL (`referrerpolicy="unsafe-url"`). `~^www\.example\.com` still accepts `www.example.com.evil.net`, `~^www.example.com/` accepts `wwwxexample.com`, and `example.*` accepts `example.evil.net`.

## Bad configuration

```nginx
valid_referers none server_names *.example.com ~\.example\.com example.*;

if ($invalid_referer) {
    return 403;
}
```

## Better configuration

```nginx
valid_referers server_names *.example.com ~^(www\.)?example\.org/;

if ($invalid_referer) {
    return 403;
}
```

Anchor every regular expression with `^` and end the host name with `/` or `:`. If missing referers must be allowed for user experience, referer validation is not a reliable security boundary for that endpoint.

## How severity is determined

- **HIGH**: `none`.
- **MEDIUM**: regular expressions or trailing wildcards that also match other sites, reported once per directive.
- **LOW**: `blocked` without `none`.

## Additional notes

- Names that `server_names` adds from the server's `server_name` are not checked.
- NGINX recognizes `none`, `blocked` and `server_names` only in lowercase; `NONE` is read as a host name.
