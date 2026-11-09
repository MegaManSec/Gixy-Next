---
title: "HTTP/2 Misdirected Request"
description: "Detects the default server of a TLS listen socket that has ssl_reject_handshake and HTTP/2 enabled but does not answer every request with 421, the safeguard against misdirected HTTP/2 requests."
---

# [http2_misdirected_request] Missing HTTP/2 misdirected-request safeguard

## What this check looks for

This plugin flags `server` blocks where all of the following are true:

- `ssl_reject_handshake on;` is in effect for the server, either set in the `server` block or inherited from the `http` block
- the server is the default server of a TLS `listen` socket: the one marked `default_server` (or `default`), or, when no server on that socket is marked, the first one in the configuration
- HTTP/2 is enabled (via `http2 on;` or `listen ... http2;`)
- the server does not answer every request with status 421

A server answers every request with 421 when either:

- `return 421;` sits directly in the `server` block, or
- a prefix `location /` (plain or `^~`) returns 421 *and* every other prefix `location` in the server, `=` ones included, returns 421 as well. Regex locations have to return 421 too, unless every prefix location carries `^~` or `=`: NGINX only consults regex locations when the longest matching prefix location has no modifier, so they are never selected otherwise. Named locations (`location @name`) and `internal` locations are not counted, since a client cannot select them directly. Nested locations are checked the same way, because `return` is not inherited into them.

## Why this is a problem

HTTP/2 allows connection reuse: a client may reuse an existing TLS connection to send a request for a different server name. When `ssl_reject_handshake on` is used on the default server to block unknown SNI names at the TLS level, this does not fully cover the HTTP/2 reuse case — some requests can still reach the server context at the HTTP layer.

RFC 7540 §9.1.2 defines status code 421 (Misdirected Request) for exactly this situation. Returning 421 gives clients an unambiguous, spec-compliant response and prevents the default server from inadvertently handling requests intended for another host.

## Bad configuration

### no 421 at all

```nginx
http {
    server {
        listen 443 ssl default_server;
        http2 on;
        ssl_reject_handshake on;
    }
}
```

### a more specific location bypasses the 421

```nginx
http {
    server {
        listen 443 ssl default_server;
        http2 on;
        ssl_reject_handshake on;
        location / {
            return 421;
        }
        location /api {
            proxy_pass http://backend;
        }
    }
}
```

NGINX picks the most specific `location`, so a misdirected request for `/api` is proxied to the backend; only the other paths get the 421.

### the default server is implicit and inherits the reject

```nginx
http {
    ssl_reject_handshake on;
    http2 on;
    server {
        listen 443 ssl;
    }
    server {
        listen 443 ssl;
        server_name example.com;
        ssl_reject_handshake off;
        ssl_certificate     /etc/ssl/example.com.crt;
        ssl_certificate_key /etc/ssl/example.com.key;
        location / {
            proxy_pass http://backend;
        }
    }
}
```

Neither server carries `default_server`, so the first one listening on `*:443` is the default. It inherits `ssl_reject_handshake on` from the `http` block and has no 421, so it is reported; the `example.com` server is not the default and is not.

## Better configuration

### return 421 for the whole server

```nginx
http {
    server {
        listen 443 ssl default_server;
        http2 on;
        ssl_reject_handshake on;
        return 421;
    }
}
```

A `return` in the `server` block runs before any `location` is selected, so every path is covered.

### return 421 from location /

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

If the default server has other locations, each of them has to return 421 too, otherwise the check reports the server.

## Additional notes

- Both the modern `http2 on;` directive (NGINX 1.25.1+) and the older `listen ... http2;` syntax are recognised.
- `location = / { return 421; }` on its own is not a safeguard: an exact match covers only `/`, and every other path falls through to NGINX's default handling.
- `ssl_reject_handshake` is inherited from `http` into `server`, and the nearest setting wins: a `server` block with `ssl_reject_handshake off;` is never reported, even under an `http` block that turns it on. Without `ssl_reject_handshake on` in effect the pattern is not in use and the check does not fire.
- Listen sockets are matched the way NGINX matches them, as in [default_server_flag](default_server_flag.md): `listen 443`, `listen *:443` and `listen 0.0.0.0:443` name one socket, `listen [::]:443` another, and `listen 443 ssl` and `listen 443 quic` each have their own default server. A `listen unix:` socket is only considered when it is marked `default_server`.
