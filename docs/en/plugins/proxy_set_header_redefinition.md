---
title: "Proxy Header Inheritance Issues"
description: "Detects proxy_set_header usage that unintentionally drops request headers due to inheritance rules. Declaring a single proxy_set_header in a nested block replaces every proxy_set_header inherited from the levels above it."
---

# [proxy_set_header_redefinition] Redefining proxied request headers with `proxy_set_header`

## What this check looks for

This plugin looks for nested contexts where `proxy_set_header` is used at a lower level and headers declared at higher levels are no longer sent to the upstream.

## Why this is a problem

`proxy_set_header` follows an all-or-nothing inheritance rule: the header list is inherited from the previous level only if there are no `proxy_set_header` directives at the current level. As soon as you set any header in a nested block, every header defined above it is dropped.

This is the same trap as [`add_header`](https://gixy.io/plugins/add_header_redefinition/), but the consequences land on the upstream instead of the client. The headers that usually end up missing are the ones a backend relies on for correctness and security: `Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, or an `Authorization` header for an internal API.

It also silently re-opens header spoofing. A common hardening pattern is to blank out a header so that a client cannot forge it:

```nginx
server {
    proxy_set_header X-Internal-Auth "";
}
```

If a nested block declares any `proxy_set_header` of its own, that blanking is dropped too, and a client-supplied `X-Internal-Auth` reaches the backend again.

## Bad configuration

```nginx
server {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    location /internal {
        # Looks harmless, but it drops the two headers above for /internal
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_pass http://backend;
    }
}
```

Requests to `/internal` reach the backend with only `X-Forwarded-Port`, and the backend sees no client address at all.

## Better configuration

Option 1: keep all headers at one level (often `server` or `http`), and avoid declaring them in child blocks.

```nginx
server {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Port $server_port;

    location /internal {
        proxy_pass http://backend;
    }
}
```

Option 2: if you really need headers that vary by location, repeat the inherited ones in the nested block:

```nginx
server {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    location /internal {
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_pass http://backend;
    }
}
```

A common variant of option 2 is to move the shared headers into their own file and `include` it at every level that declares headers:

```nginx
server {
    include proxy_params.conf;

    location /internal {
        include proxy_params.conf;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_pass http://backend;
    }
}
```

## Configuration

You can tune this plugin to only report on specific headers. This is useful if you only care about the headers your upstream trusts and want to ignore noise like tracing or cache tweaks.

### headers

You can use the `headers` option to only report dropped headers that match the specified list. By default, this value is empty (reports all dropped headers).

The value should be a comma-separated list of header names.

#### CLI

```bash
# The proxy_set_header_redefinition plugin will only report about dropped host and x-forwarded-for headers
gixy --proxy-set-header-redefinition-headers "host,x-forwarded-for"
```

#### Config

```ini
[proxy_set_header_redefinition]
; only report about dropped host and x-forwarded-for headers
headers = host,x-forwarded-for
```

### merge_reported_headers

By default, the plugin reports headers declared in higher scopes that are not sent to the upstream from the flagged block. This can include headers that were dropped at an intermediate scope (and remain missing further down).

If you prefer stricter "dropped at this level" reporting, you can disable this behavior so the plugin only compares against the header list inherited from the nearest ancestor that declares one.

#### CLI

```bash
# Only compare against the header list inherited from the nearest ancestor
gixy --proxy-set-header-redefinition-merge-reported-headers false
```

#### Config

```ini
[proxy_set_header_redefinition]
; only compare against the header list inherited from the nearest ancestor
merge_reported_headers = false
```

## Additional notes

### Which levels are checked

`proxy_set_header` is only valid in the `http`, `server` and `location` contexts, so the plugin reports on `server` and `location` blocks that replace headers declared above them. A `server` block that declares a header drops the `http`-level list in exactly the same way a `location` does.

### The built-in defaults still apply

NGINX always merges its own default header list on top of whatever is in effect, so `Host` and `Connection` are never left unset. Dropping `proxy_set_header Host $host;` does not remove the `Host` header, it reverts it to the default `$proxy_host`, which is the upstream address rather than the name the client asked for.

### What counts as a finding

The plugin only reports a block when something was actually inherited and is actually lost. A nested block that re-declares every inherited header is correct and is not reported, even when the values differ. A nested block whose parents declare no `proxy_set_header` at all has nothing to drop and is not reported either.

### What "dropped" means in reports

By default, this plugin reports headers that were declared in higher scopes but are not sent to the upstream from the flagged block.

In practice, that usually means the headers were dropped by the `proxy_set_header` directives inside the flagged block. However, in some configurations a header can be dropped earlier (at an intermediate scope) and remain missing further down.

If you see a report where the flagged block never inherited a header in the first place, that is expected with the default behavior: the plugin is telling you "this header is declared somewhere above, but it is not sent to the upstream here".

### How severity is determined

This plugin treats some request headers as "secure headers" and escalates severity when they are dropped. Concretely:

- If a nested block drops only non-security headers, the issue is reported as LOW.
- If a nested block drops any header from the secure list below, the issue is reported as MEDIUM.
- If a nested block drops a header that a higher scope set to an empty value, the issue is reported as MEDIUM regardless of its name.

Unlike `add_header`, these are headers sent *to the upstream*, so the list is not the usual set of response security headers. What matters here is whether the upstream loses the proxy's account of who the client is, or starts receiving a value the client chose. The following headers are considered security-sensitive:

- `host`
- `x-forwarded-for`
- `x-forwarded-host`
- `x-forwarded-proto`
- `x-real-ip`
- `forwarded`
- `authorization`
- `proxy-authorization`
- `early-data`

The empty-value rule covers the blanking pattern shown above. `proxy_set_header X-Internal-Auth "";` exists to stop a client from supplying that header, and the header name is site-specific, so it cannot be listed here by name. Losing it has the same effect as losing `X-Forwarded-For`: the upstream starts trusting a value the client controls.
