# [add_header_redefinition] Redefining response headers with `add_header`

## What this check looks for

This plugin looks for nested contexts where `add_header` is used at a lower level and headers declared at higher levels are not effective at that lower level.

## Why this is a problem

`add_header` follows an all-or-nothing inheritance rule: headers from the previous level are inherited only if there are no `add_header` directives at the current level. As soon as you add any header in a nested block, you stop inheriting every header defined above it.

That is how teams end up with security headers on most pages, but missing on "just one location".

## Bad configuration

```
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

## Better configuration

Option 1: keep all headers at one level (often `server`), and avoid redefining them in child blocks.

```
server {
    add_header X-Frame-Options "DENY";
    add_header X-Content-Type-Options "nosniff";
    add_header Cache-Control "public, max-age=86400";
}
```

Option 2: if you really need headers that vary by location, repeat the important ones in the nested block:

```
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

## Configuration

You can tune this plugin to only report on specific headers. This is useful if you only care about specific headers and want to ignore noise like caching tweaks.

### headers

You can use the `headers` option to only report dropped headers that match the specified list. By default, this value is empty (reports all dropped headers).

The value should be a comma-separated list of header names.

#### CLI

```
# The add_header_redefinition plugin will only report about dropped x-frame-options and content-security-policy headers
gixy --add-header-redefinition-headers "x-frame-options,content-security-policy"
```

#### Config

```
[add_header_redefinition]
; only report about dropped x-frame-options and content-security-policy headers
headers = x-frame-options,content-security-policy
```

### merge_reported_headers

By default, the plugin reports headers declared in higher scopes that are not effective at the flagged block. This can include headers that were dropped at an intermediate scope (and remain missing further down).

If you prefer stricter "dropped at this level" reporting, you can disable this behavior so the plugin only compares against the immediate parent's effective headers.

#### CLI

```
# Only compare against the immediate parent's effective headers
gixy --add-header-redefinition-merge-reported-headers false
```

#### Config

```
[add_header_redefinition]
; only compare against the immediate parent's effective headers
merge_reported_headers = false
```

## Additional notes

### add_header_inherit

Recent NGINX versions added `add_header_inherit` to adjust how `add_header` inherits across levels. If you have it available (nginx 1.29.3+), using `add_header_inherit merge;` prevents nested `add_header` blocks from wiping out headers defined at higher levels by merging inherited headers with headers defined at the current level. See the [documentation](https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header_inherit).

### What "dropped" means in reports

By default, this plugin reports headers that were declared in higher scopes but are not effective at the flagged block.

In practice, that usually means the headers were dropped by the `add_header` directives inside the flagged block. However, in some configurations a header can be dropped earlier (at an intermediate scope) and remain missing further down.

If you see a report where the flagged block never inherited a header in the first place, that is expected with the default behavior: the plugin is telling you "this header is declared somewhere above, but it is not in effect here".

### How severity is determined

This plugin treats some headers as "secure headers" and escalates severity when they are dropped. Concretely:

- If a nested block drops only non-security headers, the issue is reported as LOW.
- If a nested block drops any header from the secure list below, the issue is reported as MEDIUM.

The following headers are considered security-sensitive:

- `strict-transport-security`
- `content-security-policy`
- `content-security-policy-report-only`
- `x-frame-options`
- `x-content-type-options`
- `permissions-policy`
- `referrer-policy`
- `cross-origin-embedder-policy`
- `cross-origin-opener-policy`
- `cross-origin-resource-policy`
- `x-xss-protection`
- `x-permitted-cross-domain-policies`
- `expect-ct`
- `cache-control`
- `pragma`
- `expires`
- `content-disposition`
