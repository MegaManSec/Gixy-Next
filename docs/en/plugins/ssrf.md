---
title: "Server Side Request Forgery"
description: "Detects SSRF-prone proxy_pass, fastcgi_pass, uwsgi_pass, scgi_pass, and grpc_pass patterns where user input controls the upstream address. This can allow attackers to make NGINX reach internal services."
---

# [ssrf] Server Side Request Forgery

## What this check looks for

This plugin looks for `proxy_pass`, `fastcgi_pass`, `uwsgi_pass`, `scgi_pass`, or `grpc_pass` usage where the upstream address is built from variables that can be influenced by the client (host, port, and — for `proxy_pass`/`grpc_pass` — the scheme or path). That is the classic NGINX SSRF shape.

## Why this is a problem

If an attacker can control where NGINX sends a request, they can:

- scan internal networks,
- reach metadata services,
- hit admin panels that are not exposed publicly,
- and in some cases pivot into more serious compromises.

This is especially dangerous when the proxy location is intended to be "internal" but can be reached via rewrites, error_page, try_files, or other internal redirects.

## Bad configuration

```nginx
location ~* ^/internal-proxy/(?<proxy_proto>https?)/(?<proxy_host>.*?)/(?<proxy_path>.*)$ {
    internal;

    proxy_pass $proxy_proto://$proxy_host/$proxy_path;
    proxy_set_header Host $proxy_host;
}
```

Marking a location `internal` helps, but it does not automatically make the whole setup safe if other directives can route a request into it.

A common mistake is combining an unsafe rewrite with the internal proxy:

```nginx
rewrite ^/(.*)/some$ /$1/ last;

location ~* ^/internal-proxy/(?<proxy_proto>https?)/(?<proxy_host>.*?)/(?<proxy_path>.*)$ {
    internal;
    proxy_pass $proxy_proto://$proxy_host/$proxy_path;
}
```

## Better configuration

If the set of upstream hosts is small, hardcode them and select with a `map`:

```nginx
map $arg_target $upstream_host {
    default "";
    one "backend1.internal";
    two "backend2.internal";
}

server {
    location /proxy/ {
        if ($upstream_host = "") { return 400; }

        proxy_pass http://$upstream_host;
        proxy_set_header Host $upstream_host;
    }
}
```

If you cannot enumerate hosts, treat the upstream address as a signed token (HMAC) rather than raw client input, and verify it before proxying.

## Additional notes

Variable-based proxying is not inherently insecure, but the moment the variable is derived from user input, you need a tight allowlist and a plan for internal redirect paths (`rewrite`, `error_page`, `try_files`, X-Accel-Redirect, and subrequests).
