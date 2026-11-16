---
title: "Server Side Request Forgery"
description: "Detects SSRF-prone proxy_pass, fastcgi_pass, uwsgi_pass, scgi_pass, and grpc_pass patterns where user input controls the upstream address. This can allow attackers to make NGINX reach internal services."
---

# [ssrf] Server Side Request Forgery

## What this check looks for

This plugin looks for `proxy_pass`, `fastcgi_pass`, `uwsgi_pass`, `scgi_pass`, or `grpc_pass` usage where the upstream address is built from variables that can be influenced by the client (host, port, and — for `proxy_pass`/`grpc_pass` — the scheme or path). That is the classic NGINX SSRF shape.

`$host` counts as client input only where a request for any host name can reach the server: the default server of a `listen` socket (the one flagged `default_server`, or the first one declared on that socket), or a server whose `server_name` is a catch-all regular expression such as `~.`. With a `resolver`, it also counts in a server whose `server_name` matches domains the client can register, such as `example.*`, `~^api\.` or `~^api\.(.+)$`. Deciding that needs the full configuration, so `$host` is only considered when an `http` block is present.

## Why this is a problem

If an attacker can control where NGINX sends a request, they can:

- scan internal networks,
- reach metadata services,
- hit admin panels that are not exposed publicly,
- and in some cases pivot into more serious compromises.

This is especially dangerous when the proxy location is intended to be "internal" but can be reached via rewrites, error_page, try_files, or other internal redirects.

## Bad configuration

```nginx
location ~* ^/proxy/(?<proxy_proto>https?)/(?<proxy_host>.*?)/(?<proxy_path>.*)$ {
    proxy_pass $proxy_proto://$proxy_host/$proxy_path;
    proxy_set_header Host $proxy_host;
}
```

Any client can make NGINX request any host, for example `/proxy/http/169.254.169.254/latest/meta-data/`.

The host is whatever precedes the first `/` of the address, so a client-controlled value (`$arg_*`, `$cookie_*`, `$http_*`) at the start of a `set` value still picks the host even when a fixed path follows it:

```nginx
location / {
    set $backend "$cookie_backend/";
    proxy_pass http://$backend;
}
```

Marking such a location `internal` stops clients from requesting it directly, so the plugin does not report it, nor the nested locations and `limit_except` blocks inside it. A `rewrite` can still route a request into it:

```nginx
server {
    rewrite ^/(.*)/some$ /$1/ last;

    location ~* ^/internal-proxy/(?<proxy_proto>https?)/(?<proxy_host>.*?)/(?<proxy_path>.*)$ {
        internal;
        proxy_pass $proxy_proto://$proxy_host/$proxy_path;
    }
}
```

### host header in the default server

```nginx
http {
    server {
        listen 80 default_server;
        location / {
            proxy_pass http://$host$request_uri;
        }
    }
}
```

`$host` is the request's Host header after NGINX has validated and lowercased it. Every request whose host name matches no other server lands in the default server, so `Host: 169.254.169.254` makes NGINX fetch the metadata service. A server with a fixed `server_name` is the default too when it is the first one declared on its socket.

### host header with an open-ended server name

```nginx
http {
    resolver 127.0.0.53;
    server {
        listen 80 default_server;
        server_name _;
        return 444;
    }
    server {
        listen 80;
        server_name example.*;
        location / {
            proxy_pass http://$host$request_uri;
        }
    }
}
```

`example.*` also matches `example.attacker.net`. The attacker points that name at any address in their own DNS, and the `resolver` makes NGINX connect there.

## Better configuration

If the set of upstream hosts is small, define them as `upstream` blocks and select one with a `map`:

```nginx
upstream backend1 {
    server 10.0.0.11:8080;
}

upstream backend2 {
    server 10.0.0.12:8080;
}

map $arg_target $upstream_name {
    default "";
    one backend1;
    two backend2;
}

server {
    location /proxy/ {
        if ($upstream_name = "") { return 400; }

        proxy_pass http://$upstream_name;
    }
}
```

Because the variable always names an `upstream` block, NGINX needs no `resolver` to look it up.

In `stream`, map `$ssl_preread_server_name` to a fixed set of upstreams with a `default` instead of proxying to it directly.

If you cannot enumerate hosts, treat the upstream address as a signed token (HMAC) rather than raw client input, and verify it before proxying.

## Additional notes

Variable-based proxying is not inherently insecure, but the moment the variable is derived from user input, you need a tight allowlist and a plan for internal redirect paths (`rewrite`, `error_page`, `try_files`, X-Accel-Redirect, and subrequests).

In a server that is not the default of any of its sockets and lists fixed `server_name`s, `$host` can only be one of those names, so it is not reported. Leading wildcard names such as `*.example.com`, and regular expressions that end in a fixed domain such as `~^(.+)\.example\.com$`, are not reported either: an attacker would need to control DNS under that zone to point `$host` at another address.

`$ssl_server_name` is the TLS server name (SNI) the client sent, copied by NGINX without validation, so `proxy_pass https://$ssl_server_name` is reported like any other client-controlled host. So is `$ssl_preread_server_name` in a `stream` server.

The plugin checks an `internal` location when a `rewrite` in the same `server` can send a request there: one whose replacement is built from variables and whose fixed start can match the location, at `server` level with any flag, or in a location with `last` or no flag.
