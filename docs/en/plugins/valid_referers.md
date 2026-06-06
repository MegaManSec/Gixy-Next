---
title: "Referer Check Bypass"
description: "Detects use of 'none' or 'blocked' in valid_referers. Both accept requests that cannot prove a legitimate HTTP Referer, which an attacker can trivially produce."
---

# [valid_referers] `none`/`blocked` in `valid_referers`

## What this check looks for

This plugin warns when `valid_referers` includes the `none` or `blocked` keyword.

## Why this is a problem

`none` means: treat requests with no `Referer` header as valid. `blocked` means: treat requests whose `Referer` is present but has had its scheme stripped (for example deleted by a proxy or firewall, so the value does not start with `http://`/`https://`) as valid.

The trouble is that both classes are trivially attacker-producible. The `Referer` header is optional — users and browsers can drop it for perfectly normal reasons (HTTPS to HTTP redirects, referrer policy, opaque origins, `data:` URLs), and an attacker can omit it deliberately or send a scheme-less value such as `Referer: deleted` to match `blocked`. If you accept `none` or `blocked`, a client can bypass your referer-based control simply by controlling whether and how the header is sent.

## Bad configuration

```nginx
valid_referers none server_names *.example.com;

if ($invalid_referer) {
    return 403;
}
```

With `none` allowed, a request without `Referer` will not be considered invalid.

## Better configuration

If you rely on referer checking, be strict:

```nginx
valid_referers server_names *.example.com;

if ($invalid_referer) {
    return 403;
}
```

Then decide what you want to do for missing referers. If missing referers must be allowed for user experience, referer validation is not a reliable security boundary for that endpoint.
