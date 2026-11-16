---
title: "Missing default_server Flag"
description: "Detects listen sockets shared by multiple server blocks where none is marked as default_server, making unmatched hostnames ambiguous."
---

# [default_server_flag] Missing `default_server` on shared listen socket

## What this check looks for

This plugin reports when multiple `server` blocks share the same `listen` address and port, but none of them is marked as `default_server` (or `default`).

## Why this is a problem

When a request's host name matches no `server_name`, NGINX routes it to the default server for that socket. Without the flag, that is whichever `server` was declared first, so the choice changes when files are reordered or included differently, and requests can land on the wrong virtual host and get its content or certificate.

## Bad configuration

```nginx
http {
    # HTTP vhosts share :80, but no default_server
    server {
        listen 80;
        server_name a.test;

        return 301 https://a.test$request_uri;
    }

    server {
        listen 80;
        server_name b.test;

        return 301 https://b.test$request_uri;
    }

    # HTTPS vhosts share :443, but no default_server
    server {
        listen 443 ssl;
        server_name a.test;

        ssl_certificate     /etc/ssl/a.test.crt;
        ssl_certificate_key /etc/ssl/a.test.key;

        location / { return 200 "a\n"; }
    }

    server {
        listen 443 ssl;
        server_name b.test;

        ssl_certificate     /etc/ssl/b.test.crt;
        ssl_certificate_key /etc/ssl/b.test.key;

        location / { return 200 "b\n"; }
    }
}
```

Requests for an unknown host name go to whichever server is declared first on each socket.

## Better configuration

Pick the server you want as the catch-all and mark it explicitly:

```nginx
http {
    # Explicit default for HTTP :80
    server {
        listen 80 default_server;
        server_name _;

        return 444;
    }

    # Explicit default for HTTPS :443
    server {
        listen 443 ssl default_server;
        server_name _;

        # A dedicated/default cert (self-signed or otherwise) for unknown names
        ssl_certificate     /etc/ssl/default.crt;
        ssl_certificate_key /etc/ssl/default.key;

        return 444;
    }
}
```

The `a.test` and `b.test` servers stay as they are.

## Additional notes

This plugin only runs on a full configuration, one with a top-level `http` or `events` block.

Sockets are compared the way NGINX itself compares them. `listen 80`, `listen *:80`, `listen 0.0.0.0:80` and `listen 0.0.0.0` all name one socket, as do `listen [::]:80`, `listen [::0]:80` and `listen [::]`; an argument with no port implies port 80. The IPv4 and IPv6 wildcards on one port stay separate, and so do sockets of different types: `listen 443 ssl` and `listen 443 quic` each have their own default server, as do `listen 12345` and `listen 12345 udp` in `stream`.

`listen localhost` is compared as `127.0.0.1`. Depending on the libc and the host's IPv6 setup, NGINX may also bind `[::1]`; that socket is not assumed. Other hostnames are compared by name.

`listen unix:/path` sockets are matched by their path.

An `http` `server` block with no `listen` directive at all still takes part in the check: NGINX gives it `*:80` when running as the superuser (`*:8000` otherwise), so it shares the socket with any `listen 80;` sibling. Because the scanned configuration says nothing about the user NGINX will run as, the check assumes the `*:80` case.

`server` blocks are only compared within their own module, so an `http` server and a `stream` server on the same port are not reported against each other.
