---
title: "Header Inheritance Issues"
description: "Detects add_header and add_trailer usage that unintentionally drops fields due to inheritance rules. Adding a header in a nested block replaces inherited add_header values unless add_header_inherit merge is enabled (nginx 1.29.3+)."
---

# [add_header_redefinition] Redefining response headers with `add_header`

## What this check looks for

This plugin looks for nested contexts where `add_header` is used at a lower level and headers declared at higher levels are not effective at that lower level. The same check is applied to `add_trailer`, which follows the identical inheritance rule.

It also reports nested contexts that inherit `add_header_inherit off` (or `add_trailer_inherit off`) and so lose the fields of the level above. A block that declares `off` itself is not reported.

## Why this is a problem

`add_header` follows an all-or-nothing inheritance rule: headers from the previous level are inherited only if there are no `add_header` directives at the current level. As soon as you add any header in a nested block, you stop inheriting every header defined above it.

That is how teams end up with security headers on most pages, but missing on "just one location".

## Bad configuration

### add_header in a nested block

```nginx
server {
    add_header X-Frame-Options "DENY";
    add_header X-Content-Type-Options "nosniff";

    location /static/ {
        # Looks harmless, but it drops the two headers above for /static/
        add_header Cache-Control "public, max-age=86400";
    }
}
```

Requests under `/static/` will only get `Cache-Control`, and the security headers vanish.

### inherited add_header_inherit off

```nginx
http {
    add_header X-Powered-By "example";

    server {
        add_header_inherit off;
        add_header X-Frame-Options "DENY";

        location / {
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
```

The `location` inherits `off` as well, so it sends no `X-Frame-Options`.

## Better configuration

### add_header in a nested block

Option 1: keep all headers at one level (often `server`), and avoid redefining them in child blocks.

```nginx
server {
    add_header X-Frame-Options "DENY";
    add_header X-Content-Type-Options "nosniff";
    add_header Cache-Control "public, max-age=86400";
}
```

Option 2: if you really need headers that vary by location, repeat the important ones in the nested block:

```nginx
server {
    add_header X-Frame-Options "DENY";
    add_header X-Content-Type-Options "nosniff";

    location /static/ {
        add_header X-Frame-Options "DENY";
        add_header X-Content-Type-Options "nosniff";
        add_header Cache-Control "public, max-age=86400";
    }
}
```

### add_header_inherit off

Set `add_header_inherit on;` (or `merge;`) in the nested blocks that should keep the headers of the level that declares `off`.

## Configuration

You can tune this plugin to only report on specific headers. This is useful if you only care about specific headers and want to ignore noise like caching tweaks.

### headers

You can use the `headers` option to only report dropped headers that match the specified list. By default, this value is empty (reports all dropped headers).

The value should be a comma-separated list of header names.

#### CLI

```bash
# The add_header_redefinition plugin will only report about dropped x-frame-options and content-security-policy headers
gixy --add-header-redefinition-headers "x-frame-options,content-security-policy"
```

#### Config

```ini
[add_header_redefinition]
; only report about dropped x-frame-options and content-security-policy headers
headers = x-frame-options,content-security-policy
```

### merge_reported_headers

By default, the plugin reports headers declared in higher scopes that are not effective at the flagged block. This can include headers that were dropped at an intermediate scope (and remain missing further down).

If you prefer stricter "dropped at this level" reporting, you can disable this behavior so the plugin only compares against the immediate parent's effective headers.

#### CLI

```bash
# Only compare against the immediate parent's effective headers
gixy --add-header-redefinition-merge-reported-headers false
```

#### Config

```ini
[add_header_redefinition]
; only compare against the immediate parent's effective headers
merge_reported_headers = false
```

## How severity is determined

- **MEDIUM**: a dropped response header is on the list below.
- **LOW**: any other dropped header, and every dropped trailer.

Security-sensitive headers: `strict-transport-security`, `content-security-policy`, `content-security-policy-report-only`, `x-frame-options`, `x-content-type-options`, `permissions-policy`, `referrer-policy`, `cross-origin-embedder-policy`, `cross-origin-opener-policy`, `cross-origin-resource-policy`, `x-xss-protection`, `x-permitted-cross-domain-policies`, `expect-ct`, `cache-control`, `pragma`, `expires` and `content-disposition`.

## Additional notes

- With nginx 1.29.3+, `add_header_inherit merge;` merges inherited headers with those of the current level, so a nested `add_header` no longer drops them. See the [documentation](https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header_inherit).
- `add_trailer` and `add_trailer_inherit` follow the same rules, but NGINX keeps trailers and headers apart: a nested `add_trailer` drops inherited trailers only, and a nested `add_header` drops inherited headers only. Each drop is reported on its own.
