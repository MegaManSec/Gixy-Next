---
title: "Duplicate Content-Type"
description: "Flags setting Content-Type via add_header, which creates a duplicate Content-Type header unless the upstream's header is hidden by the matching *_hide_header. Prefer an empty types block with default_type."
---

# [add_header_content_type] Using `add_header` to set `Content-Type`

## What this check looks for

This plugin flags `add_header` directives that set the `Content-Type` response header. The header name is matched case-insensitively.

A location that proxies to an upstream is not reported when the upstream's `Content-Type` is hidden by the `*_hide_header` directive of the module that does the proxying: `proxy_hide_header` for `proxy_pass`, `fastcgi_hide_header` for `fastcgi_pass`, and likewise for `uwsgi_pass`, `scgi_pass` and `grpc_pass`. When the scope has no `*_pass` directive, a `Content-Type` hidden by any of the five modules is accepted.

## Why this is a problem

NGINX can end up sending two `Content-Type` headers: the one it sets from `types` or receives from the upstream, and the one you added. Different clients handle duplicates differently, and caches may store an unexpected value.

## Bad configuration

### plain add_header

```nginx
add_header Content-Type text/plain;
```

If your backend returns `Content-Type: application/json`, the response contains both headers.

### hide directive of the wrong module

```nginx
location / {
    fastcgi_hide_header Content-Type;
    proxy_pass http://127.0.0.1:8080;
    add_header Content-Type text/plain;
}
```

`fastcgi_hide_header` only affects `fastcgi_pass` responses, so the `proxy_pass` response keeps the upstream `Content-Type` and the client receives two.

### hide list redeclared in the location

```nginx
server {
    proxy_hide_header Content-Type;

    location / {
        proxy_hide_header X-Other;
        proxy_pass http://127.0.0.1:8080;
        add_header Content-Type text/plain;
    }
}
```

A level that declares its own `proxy_hide_header` list replaces the inherited one, so the `location` no longer hides `Content-Type` and the upstream header reaches the client.

### pass_header re-exposes the upstream header

```nginx
server {
    proxy_hide_header Content-Type;

    location / {
        proxy_pass_header Content-Type;
        proxy_pass http://127.0.0.1:8080;
        add_header Content-Type text/plain;
    }
}
```

The `location` inherits the hide list, but its `proxy_pass_header Content-Type` takes the header out of it again, so the upstream header reaches the client alongside the added one.

## Better configuration

### static content

```nginx
location /downloads/ {
    types { }
    default_type text/plain;
}
```

`default_type` applies only to extensions missing from `types`, so on its own it does not change a `.html` file. The empty `types` block makes every response in the location use it.

### proxied content

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_hide_header Content-Type;
    add_header Content-Type "application/octet-stream";
}
```

`default_type` does not change a proxied response. Hide the upstream header with the `*_hide_header` directive of the module you proxy with, then add your own.

## Additional notes

`more_set_headers "Content-Type: ..."` from the headers-more module is not reported. It writes the response's content type directly instead of appending a header, so it replaces the upstream value rather than duplicating it.
