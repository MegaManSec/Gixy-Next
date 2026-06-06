---
title: "Weak Referer/Origin Validation"
description: "Flags unsafe or brittle Origin/Referer validation logic (most often loose regex checks) that can weaken clickjacking and CORS protections by accidentally trusting attacker-controlled inputs."
---

# [origins] Weak `Referer` / `Origin` validation

This check looks for common mistakes when using `$http_origin` or `$http_referer` to gate security behavior (CORS, clickjacking headers, etc.). It covers brittle regex-based validation in `if` conditions and `map`-based CORS allowlists, as well as configurations that reflect the request `Origin` into `Access-Control-Allow-Origin` unconditionally.

## What it detects

### Regex that can be bypassed to match an untrusted domain

Examples of bypasses this plugin tries to find:

- Suffix injection: `https://good.example.com.evil.com`
- Prefix injection: `http://evil.com/?https://good.example.com`
- Scheme confusion (when you meant to require https): `http://good.example.com`

### Invalid values that should never be treated as a valid Origin/Referer

The plugin reports patterns that accept values that are syntactically invalid for the header being validated:

- Origin must be: `<scheme>://<hostname>[:port]` (no path, query, or fragment).
- Referer should be an absolute URL including scheme and hostname.

It can also flag values that contain uppercase letters or unusual characters in the scheme/host.

### Common header typo

`$http_referrer` is not a valid NGINX variable for the HTTP Referer header. The correct variable is `$http_referer`.

### Unconditional reflection of the Origin

Reflecting `$http_origin` straight back into `Access-Control-Allow-Origin` accepts *any* origin — there is no allowlist at all. The plugin flags this whether the request Origin is reflected directly, through a `set`, or via a non-regex `map` default:

```nginx
# Direct reflection — every origin is allowed
add_header Access-Control-Allow-Origin $http_origin always;

# Indirect, via set
set $cors $http_origin;
add_header Access-Control-Allow-Origin $cors always;

# Non-regex map that defaults to reflecting the origin
map $http_origin $cors {
    default $http_origin;
}
add_header Access-Control-Allow-Origin $cors always;
```

A literal-key `map` allowlist (for example `https://trusted.example $http_origin;` with a safe `default`) is *not* flagged: only the listed origins are echoed back. Like the `map` analysis below, this detection runs only on a full configuration scan (one that includes an `http { .. }` block).

## Why this is a problem

Origin and Referer are attacker-controlled request headers. If your config uses them to decide whether to:

- set `Access-Control-Allow-Origin`,
- set `X-Frame-Options` / `Content-Security-Policy: frame-ancestors`,
- enable credentials (`Access-Control-Allow-Credentials: true`),

then a slightly-wrong regex can silently turn a strict policy into "trust anything that looks kind of right".

Regex allowlists are especially easy to get wrong when you combine:

- alternation (`|`),
- partial anchoring (`^` without `$`, or vice versa),
- match-any-character dots (`.`),
- optional groups,
- subdomain handling,
- ports,
- scheme handling.

## What triggers a finding

You will typically see findings in these patterns:

### `if`-based validation

```nginx
# Intended: allow only yandex.ru
# Risk: also matches https://metrika-hacked-yandex.ru/
if ($http_referer !~ "^https://([^/])+metrika.*yandex\.ru/") {
    add_header X-Frame-Options SAMEORIGIN;
}
```

The above case is an example of a MEDIUM finding. The referer regex can be bypassed to match an untrusted domain.

```nginx
# Invalid for Origin: origin cannot contain a path
if ($http_origin !~ "^https://yandex\.ru/$") {
    add_header X-Frame-Options SAMEORIGIN;
}
```

The above example is a LOW finding. The regex matches an invalid Origin (the Origin must not include a path, even `/`).

```nginx
# Wrong variable name (typo)
if ($http_referrer !~ "^https://yandex\.ru/") {
    add_header X-Frame-Options SAMEORIGIN;
}
```

The above example is a HIGH finding. The config is using the wrong variable (`referer` vs. `referrer`).

### `map`-based CORS allowlists that reflect an origin

The plugin also inspects this common pattern:

```nginx
# Invalid origin reflected: matches subdomain5example.com
map $http_origin $allow_origin {
    default "";
    ~^https://subdomain.example.com$ $http_origin;
}

add_header Access-Control-Allow-Origin $allow_origin always;
```

If the `map` regex can be bypassed (or matches invalid Origin forms), you can end up reflecting a hostile origin.

Note: scanning of *this* pattern (defining `access-control-allow-origin` based on a map) occurs only when a full configuration is performed, i.e. when the configuration scanned includes an `http { .. }` block.

## Bad configuration

```nginx
# Intended to allow only yandex domains, but can also match:
# https://www.yandex.ru.evil.com
if ($http_origin ~* ((^https://www\.yandex\.ru)|(^https://ya\.ru)$)) {
    add_header Access-Control-Allow-Origin "$http_origin";
    add_header Access-Control-Allow-Credentials "true";
}
```

Common issues here:

- alternation with uneven anchoring,
- missing `$` anchors,
- reflecting `$http_origin` directly when the allowlist is not strict.

## Safer configuration patterns

### Prefer `map` with a strict allowlist and controlled reflection

```nginx
map $http_origin $allow_origin {
    default "";

    # Allow example.com and any subdomain, optional port, https only.
    ~^https://([A-Za-z0-9-]+\.)?example\.com(?::[0-9]{1,5})?$ $http_origin;
}

add_header Access-Control-Allow-Origin $allow_origin always;
add_header Access-Control-Allow-Credentials "true" always;
```

This is better because:

- only allowlisted origins are reflected,
- everything else becomes an empty value,
- the pattern is fully anchored and describes the full Origin syntax.

### Keep Origin rules strict (Origin has no path)

If you need to validate `Origin`, always anchor the entire value, including any optional port.

Good structure to aim for:

- `^https://`
- optional subdomain
- exact registrable domain
- optional `:port`
- `$`

## Notes for Referer validation

If your goal is anti-hotlinking or basic referer checks, consider using `valid_referers` (see the [`ngx_http_referer_module` documentation](https://nginx.org/en/docs/http/ngx_http_referer_module.html)) instead of hand-rolled regex in `if`. It is not perfect, but it is easier to audit than ad-hoc patterns.

## Configuration

This plugin has a few knobs you can use to decide how strict you want it to be.

### domains

You can use the `domains` option to define a trusted allowlist of registrable domains. If the regex can be bypassed to match a different domain, the plugin will flag it as insecure.

By default, this is `*`, which disables domain allowlisting checks.

#### CLI

```bash
# Only treat origins/referers under example.com and example.org as trusted
gixy --origins-domains "example.com,example.org"
```

#### Config

```ini
[origins]
; allowlist trusted registrable domains (use "*" to disable allowlisting)
domains = example.com,example.org
```

### https-only

You can use the `https-only` option to require the https scheme. When enabled, patterns that allow `http://` will be flagged as insecure.

By default, this is `false`.

#### CLI

```bash
# Only allow https origins/referers
gixy --origins-https-only true
```

#### Config

```ini
[origins]
; require https scheme in origins/referers
https-only = true
```

### lower-hostname

You can use the `lower-hostname` option to enforce lowercase scheme/hostname expectations. When enabled, patterns that accept uppercase or unusual characters in the scheme/host are treated as invalid.

By default, this is `true`. Only disable this if you really know what you're doing (hostnames are nearly always case insensitive!)

#### CLI

```bash
# Disable lowercase validation
gixy --origins-lower-hostname false
```

#### Config

```ini
[origins]
; enforce lowercase scheme/hostname checks
lower-hostname = true
```

## Additional notes

This plugin uses different severities depending on what it finds, and which header is involved. The logic is generally quite simple:

- If the regex matches an *insecure* `Origin`, the severity is HIGH.
- If the regex matches an *invalid* `Origin` or `Referer`, the severity is LOW.
- If the regex matches an insecure `Referer`, the severity is MEDIUM.
- If `$http_referrer` is used, the severity is HIGH.

The check for the invalid `map`-based CORS header is only performed when a full configuration scan occurs, i.e. when the configuration scanned includes an `http { .. }` block.
