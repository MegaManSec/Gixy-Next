---
title: "Proxy Buffering Disabled"
description: "Flags proxy_buffering off, its fastcgi, uwsgi and scgi equivalents, and the request_buffering directives set to off. Without buffering, a slow client holds the backend worker serving it for the whole transfer."
---

# [proxy_buffering_off] Disabling upstream buffering

## What this check looks for

This plugin reports these directives when they are explicitly set to `off`:

- response buffering: `proxy_buffering`, `fastcgi_buffering`, `uwsgi_buffering`, `scgi_buffering`
- request body buffering: `proxy_request_buffering`, `fastcgi_request_buffering`, `uwsgi_request_buffering`, `scgi_request_buffering`

## Why this is a problem

Without buffering, NGINX passes the response or request body at the client's pace, so a slow download or upload keeps the upstream connection, and the backend worker serving it, busy for the whole transfer. Backends with a fixed number of workers, such as PHP-FPM, can be exhausted by a handful of slow clients.

## Bad configuration

```nginx
location /api/ {
    proxy_pass http://upstream;
    proxy_buffering off;
}
```

## Better configuration

```nginx
location /api/ {
    proxy_pass http://upstream;
    proxy_buffering on;
}
```

Both kinds of buffering are on by default, so removing the `off` lines is enough.

## How severity is determined

- **MEDIUM**: response buffering is off.
- **LOW**: request body buffering is off. Large uploads are often streamed on purpose.

## Additional notes

- Disabling buffering can be intentional for streaming (SSE, long polling, large transfers). The plugin still reports it; skip the check with `--skips proxy_buffering_off`.
- `grpc_pass` always streams and has no buffering directive, so it is not checked.
