---
title: "HTTP/2 Misdirected Request"
description: "Detects a TLS default server with ssl_reject_handshake and HTTP/2 or HTTP/3 that does not answer every request with 421, the safeguard against misdirected requests."
---

# [http2_misdirected_request] Missing HTTP/2 misdirected-request safeguard

## What this check looks for

This plugin flags `server` blocks where all of the following are true:

- `ssl_reject_handshake on;` is in effect for the server, either set in the `server` block or inherited from the `http` block
- the server is the default server of a TLS `listen` socket: the one marked `default_server` (or `default`), or, when no server on that socket is marked, the first one in the configuration
- another server on the same socket accepts TLS handshakes (has no `ssl_reject_handshake on;`), so connections to the socket can complete
- the protocol is enabled for the server:
  - on a TCP socket, `http2 on;` is in effect for it, or any server on the socket has `listen ... http2`, which applies to the whole socket
  - on a QUIC socket (`listen ... quic`), `http3` is not turned off; it is on by default
- `ssl_verify_client` is not in effect for the server
- the server does not answer every request with status 421

A server answers every request with 421 when either:

- `return 421;` sits directly in the `server` block, or
- a prefix `location /` (plain or `^~`) returns 421 *and* every other prefix `location` in the server, `=` ones included, returns 421 as well. Regex locations have to return 421 too, unless every prefix location carries `^~` or `=`: NGINX only consults regex locations when the longest matching prefix location has no modifier, so they are never selected otherwise. Named locations (`location @name`) and `internal` locations are not counted, since a client cannot select them directly. Nested locations are checked the same way, because `return` is not inherited into them.

## Why this is a problem

HTTP/2 and HTTP/3 clients may reuse a TLS connection opened for one server to send a request for another name. `ssl_reject_handshake` only acts at the handshake, so NGINX hands a request for a name that no server handles to the socket's default server. NGINX answers it with 421 on its own only when the default server has that protocol disabled or sets `ssl_verify_client`; otherwise the default server's locations handle it. HTTP/1.1 requests with a foreign `Host` header reach it the same way.

RFC 7540 §9.1.2 defines status code 421 (Misdirected Request) for exactly this situation.

## Bad configuration

### no 421 at all

```nginx
http {
    server {
        listen 443 ssl default_server;
        http2 on;
        ssl_reject_handshake on;
    }
    server {
        listen 443 ssl;
        server_name example.com;
        http2 on;
        ssl_certificate     /etc/ssl/example.com.crt;
        ssl_certificate_key /etc/ssl/example.com.key;
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
    server {
        listen 443 ssl;
        server_name example.com;
        http2 on;
        ssl_certificate     /etc/ssl/example.com.crt;
        ssl_certificate_key /etc/ssl/example.com.key;
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

Neither server carries `default_server`, so the first one on `*:443` is the default. It inherits `ssl_reject_handshake on` and has no 421.

### an HTTP/3 listener

```nginx
http {
    server {
        listen 443 ssl default_server;
        listen 443 quic default_server;
        ssl_reject_handshake on;
    }
    server {
        listen 443 ssl;
        listen 443 quic;
        server_name example.com;
        http2 on;
        ssl_certificate     /etc/ssl/example.com.crt;
        ssl_certificate_key /etc/ssl/example.com.key;
    }
}
```

NGINX answers misdirected HTTP/2 requests with 421 itself, since the default server does not enable HTTP/2, but `http3` is on by default, so HTTP/3 requests reach it.

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
    server {
        listen 443 ssl;
        server_name example.com;
        http2 on;
        ssl_certificate     /etc/ssl/example.com.crt;
        ssl_certificate_key /etc/ssl/example.com.key;
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
    server {
        listen 443 ssl;
        server_name example.com;
        http2 on;
        ssl_certificate     /etc/ssl/example.com.crt;
        ssl_certificate_key /etc/ssl/example.com.key;
    }
}
```

If the default server has other locations, each of them has to return 421 too, otherwise the check reports the server.

## Additional notes

- Both the modern `http2 on;` directive (NGINX 1.25.1+) and the older `listen ... http2;` syntax are recognised.
- `location = / { return 421; }` on its own is not a safeguard: an exact match covers only `/`, and every other path falls through to NGINX's default handling.
- Listen sockets are matched the way NGINX matches them, as in [default_server_flag](default_server_flag.md): `listen 443`, `listen *:443` and `listen 0.0.0.0:443` name one socket, `listen [::]:443` another, and `listen 443 ssl` and `listen 443 quic` each have their own default server. A `listen unix:` socket is only considered when it is marked `default_server`.
