---
title: "Regex Denial of Service"
description: "Detects regular expressions that can backtrack catastrophically (ReDoS), so each crafted request costs a worker CPU until PCRE2's match limit stops it."
---

# [regex_redos] Regular expression denial of service (ReDoS)

## What this check looks for

Regular expressions that may backtrack catastrophically ([ReDoS](https://en.wikipedia.org/wiki/ReDoS)), in:

- `location ~ ...`, `if ($var ~ ...)`, `server_name ~ ...`, `rewrite ...` and `map` regex keys,
- `gzip_disable` (matched against `User-Agent`), `valid_referers ~...` (matched against `Referer`) and `fastcgi_split_path_info` (matched against the URI).

## Why this is a problem

An ambiguous pattern, such as nested quantifiers, can take exponential time on crafted input. NGINX uses PCRE2's default match limit, so each such request costs the worker about 0.1 s of CPU (less with `pcre_jit`) and logs `pcre2_match() failed: -47`. A `location` or `if` match that hits the limit also fails the request with 500.

## Bad configuration

```nginx
location ~ (a+)+$ {
    return 200 "ok";
}
```

## Better configuration

Avoid nested quantifiers such as `(a+)+` or `(.*)+`, keep alternations unambiguous, and test patterns with [recheck](https://makenowjust-labs.github.io/recheck/playground/):

```nginx
location ~ ^a+$ {
    return 200 "ok";
}
```

## Configuration

This plugin is opt-in. It does not run unless you point it at a ReDoS checking service.

### url

The plugin POSTs each regex to this URL and expects a response in the `recheck` JSON format, for example from [recheck-http-api](https://github.com/megamansec/recheck-http-api). By default it is empty and the plugin skips.

#### CLI

```bash
gixy --regex-redos-url "http://127.0.0.1:8080/"
```

#### Config

```ini
[regex_redos]
url = http://127.0.0.1:8080/
```

## Additional notes

- A regex the checker reports as vulnerable is MEDIUM. Nothing is reported when the checker cannot decide or cannot be reached, or when the `requests` package is missing.
- More background: [ReDoS in nginx directives](https://joshua.hu/nginx-directives-regex-redos-denial-of-service-vulnerable).
