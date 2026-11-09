---
title: "Duplicate Content-Type"
description: "Flags setting Content-Type via add_header, which creates a duplicate Content-Type header unless the upstream's header is hidden by the matching *_hide_header. Prefer default_type."
---

# [add_header_content_type] Using `add_header` to set `Content-Type`

## What this check looks for

This plugin looks for configurations that set the `Content-Type` response header using `add_header`. The header name is matched case-insensitively.

A location that proxies to an upstream is not reported when the upstream's `Content-Type` is hidden by the `*_hide_header` directive of the module that does the proxying: `proxy_hide_header` for `proxy_pass`, `fastcgi_hide_header` for `fastcgi_pass`, and likewise for `uwsgi_pass`, `scgi_pass` and `grpc_pass`. Each upstream module keeps its own hide list, so a `fastcgi_hide_header` has no effect on a `proxy_pass` response. When the scope has no `*_pass` directive, a `Content-Type` hidden by any of the five modules is accepted.

The hide list in effect is the one from the nearest level (`location`, `server`, `http`) that declares *any* `<module>_hide_header`. A level that declares its own list replaces the inherited one rather than merging with it; `<module>_pass_header` does not reset it.

## Why this is a problem

NGINX can end up sending two `Content-Type` headers: one from the upstream, and one you added. Different clients handle duplicates differently, and caches may store an unexpected value. If you are trying to set a fallback MIME type for static content, `default_type` is the right tool.

## Bad configuration

### plain add_header

```nginx
# Adds a second Content-Type if the upstream already sets one
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

`fastcgi_hide_header` only affects `fastcgi_pass` responses. The `proxy_pass` response keeps the upstream `Content-Type`, so the client receives two.

### child list replaces the inherited one

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

The `location` declares its own `proxy_hide_header` list, so it no longer inherits `Content-Type` from the `server` level and the upstream header reaches the client.

## Better configuration

```nginx
# Sets the default MIME type for responses that do not already have one
default_type text/plain;
```

`default_type` applies when there is no explicit content type, so you avoid duplicates.

## Safe exception

If you are intentionally replacing the upstream header, hide it with the directive of the module you proxy with, then add your own:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_hide_header Content-Type;
    add_header Content-Type "application/octet-stream";
}
```

This pattern removes the upstream `Content-Type` before adding a new one, so the client sees only a single value.

The hide list is inherited as long as the `location` does not declare its own `proxy_hide_header`; `proxy_pass_header` leaves it intact:

```nginx
server {
    proxy_hide_header Content-Type;

    location / {
        proxy_pass_header X-Other;
        proxy_pass http://127.0.0.1:8080;
        add_header Content-Type "application/octet-stream";
    }
}
```

## Additional notes

`more_set_headers "Content-Type: ..."` from the headers-more module is not reported. It writes the response's content type directly instead of appending a header, so it replaces the upstream value rather than duplicating it.
