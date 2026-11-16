---
title: "HTTP/2 Misdirected Request"
description: "Detects a TLS default server with ssl_reject_handshake and HTTP/2 or HTTP/3 that does not answer every request with 421, the safeguard against misdirected requests."
---

# [http2_misdirected_request] Missing HTTP/2 misdirected-request safeguard

## What this check looks for

This plugin flags `server` blocks where all of the following are true:

- `ssl_reject_handshake on` is in effect, set in the `server` block or inherited from `http`
- the server is the default server of a TLS `listen` socket: the one marked `default_server` (or `default`), or, when none is marked, the first one on that socket in the configuration; a socket is TLS when any `listen` on it carries `ssl` or `quic`
- another server on the same socket accepts TLS handshakes, so connections to the socket can be opened at all
- the protocol is enabled for the server:
  - on a TCP socket, `http2 on` is in effect for it, or any server on the socket has `listen ... http2`, which applies to the whole socket
  - on a QUIC socket (`listen ... quic`), `http3` is not turned off; it is on by default
- `ssl_verify_client` is not enabled for the server
- the server does not answer every request with status 421

A server answers every request with 421 when either:

- `return 421;` sits directly in the `server` block, or
- `location /` (plain or `^~`) returns 421, and so does every other location a client can reach: the other prefix and `=` locations, nested locations, and regex locations unless every prefix location carries `^~` or `=` (NGINX never consults regex locations then). Nested regex locations always count: NGINX consults them whenever no nested prefix location matches, whatever modifier the enclosing location has. Named (`@name`) and `internal` locations are not counted.

## Why this is a problem

HTTP/2 and HTTP/3 clients may reuse a TLS connection opened for one server to send a request for another name. `ssl_reject_handshake` only acts at the handshake, so NGINX hands a request for a name that no server handles to the socket's default server. NGINX answers it with 421 on its own only when the default server has that protocol disabled or enables `ssl_verify_client`; otherwise the default server's locations handle it. HTTP/1.1 requests with a foreign `Host` header reach it the same way.

RFC 9113 §9.1.2 and RFC 9114 §3.3 define status code 421 (Misdirected Request) for exactly this situation.

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
- An `error_page` for 421 in effect at the `return` undoes the safeguard when it changes the status: `=NNN`, a bare `=` (the target's status) or a URL target (a redirect). A `/uri` or `@named` target without `=` keeps the 421, and a `return 421 "text";` with a body never reaches `error_page`.
- Listen sockets are matched the way NGINX matches them, as in [default_server_flag](default_server_flag.md): `listen 443`, `listen *:443` and `listen 0.0.0.0:443` name one socket, `listen [::]:443` another, and `listen 443 ssl` and `listen 443 quic` each have their own default server. `listen unix:` sockets are matched by their path.
