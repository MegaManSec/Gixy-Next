---
title: "HTTP/2 Misdirected Request"
description: "Detects TLS default_server blocks with ssl_reject_handshake and HTTP/2 enabled that are missing a location / { return 421; } safeguard against misdirected HTTP/2 requests."
---

# [http2_misdirected_request] Missing HTTP/2 misdirected-request safeguard

## What this check looks for

This plugin flags `server` blocks where all of the following are true:

- `ssl_reject_handshake on;` is present
- the server is marked `default_server` (or `default`) on a `listen` directive
- HTTP/2 is enabled (via `http2 on;` or `listen ... http2;`)
- there is no `location /` or `location = /` that returns 421

## Why this is a problem

HTTP/2 allows connection reuse: a client may reuse an existing TLS connection to send a request for a different server name. When `ssl_reject_handshake on` is used on a `default_server` to block unknown SNI names at the TLS level, this does not fully cover the HTTP/2 reuse case — some requests can still reach the server context at the HTTP layer.

RFC 7540 §9.1.2 defines status code 421 (Misdirected Request) for exactly this situation. Returning 421 from `location /` gives clients an unambiguous, spec-compliant response and prevents the default server from inadvertently handling requests intended for another host.

## Bad configuration

```nginx
http {
    server {
        listen 443 ssl default_server;
        http2 on;
        ssl_reject_handshake on;
        # no location / returning 421 — misdirected HTTP/2 requests get no explicit rejection
    }
}
```

## Better configuration

```nginx
http {
    server {
        listen 443 ssl default_server;
        http2 on;
        ssl_reject_handshake on;
        location / {
            return 421;
        }
    }
}
```

## Additional notes

- Both the modern `http2 on;` directive (NGINX 1.25.1+) and the older `listen ... http2;` syntax are recognised.
- `location = / { return 421; }` (exact match) is also accepted as a valid safeguard.
- This check only applies when `ssl_reject_handshake on` is explicitly set; without it the pattern is not in use and the check does not fire.
