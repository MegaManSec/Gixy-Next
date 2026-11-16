---
title: "Stale Upstream DNS Records"
description: "Detects proxy_pass targets whose hostnames are resolved only at startup, so the cached IP addresses can go stale. Use a variable with a resolver, or upstream server ... resolve."
---

# [stale_dns_cache] Outdated/stale cached DNS records used in proxy_pass

## What this check looks for

This plugin reports hostnames that NGINX resolves only once, at startup, so requests can go to outdated IP addresses:

- `proxy_pass` points at a literal hostname, for example `proxy_pass https://api.example.com;`
- `proxy_pass` points to an `upstream` whose `server` entries are hostnames without the `resolve` parameter
- `proxy_pass` uses a variable, or an `upstream` uses `server ... resolve`, but no `resolver` is set, so the lookup cannot happen at all

`fastcgi_pass`, `uwsgi_pass`, `scgi_pass` and `grpc_pass` are checked the same way.

## Why this is a problem

By default, NGINX resolves upstream hostnames once at startup and ignores their TTL. When the records change, traffic keeps going to the old addresses, which may now belong to another host.

To make NGINX re-resolve names at runtime, you have to opt in with either:

- a variable in `proxy_pass` plus a `resolver`, or
- `upstream` servers with the `resolve` parameter plus a `resolver` and a shared `zone` (NGINX Open Source 1.27.3+; previously NGINX Plus only).

## Bad configuration

### static hostname in proxy_pass

```nginx
location / {
    proxy_pass https://api.example.com;
}
```

### upstream uses hostnames without resolve

```nginx
upstream backend {
    server api-1.example.com;
    server api-2.example.com;
}

server {
    location / {
        proxy_pass http://backend;
    }
}
```

### variables, but without resolver

```nginx
location / {
    set $backend api.example.com;
    proxy_pass https://$backend;
}
```

Without a `resolver`, NGINX cannot look the name up and answers every request with 502.

### upstream with resolve, but no resolver

```nginx
upstream backend {
    zone backend 64k;
    server api.example.com resolve;
}

server {
    location / {
        proxy_pass http://backend;
    }
}
```

NGINX refuses to start or reload: `nginx -t` fails with "no resolver defined to resolve names at run time".

## Better configuration

### variables in proxy_pass with a resolver

```nginx
http {
    resolver 127.0.0.1 valid=30s;

    server {
        location / {
            set $backend api.example.com;
            proxy_pass https://$backend;
        }
    }
}
```

With any variable in `proxy_pass`, NGINX resolves the name at request time through the `resolver`. It honors the record's TTL unless `valid=` overrides it.

### upstream server ... resolve (open source NGINX 1.27.3+)

```nginx
http {
    resolver 127.0.0.1 valid=30s;

    upstream backend {
        zone backend 64k;
        server api.example.com resolve;
    }

    server {
        location / {
            proxy_pass http://backend;
        }
    }
}
```

`server ... resolve` re-resolves the name in the background when its TTL expires. It needs a `resolver` and a shared `zone`.

## How severity is determined

- **LOW**: the hostname has no registrable suffix, for example `backend` or `service.namespace`.
- **MEDIUM**: the hostname has a registrable suffix, for example `api.example.com`. Such names are often backed by load balancers or CDNs whose addresses change.
- **MEDIUM**: runtime re-resolution is configured (a variable in `proxy_pass`, or `server ... resolve`) but no `resolver` is set, so proxying does not work at all.

## Additional notes

- IP addresses and `unix:` sockets need no lookup and are not reported, nor is a variable whose values are all of those, such as a `map` or `geo` that picks a PHP-FPM socket, or a value that passes through `set` in either direction.
- A target selects an `upstream` the way NGINX does: by host name, case-insensitively, whatever the scheme, and only without an explicit port. `proxy_pass http://$up:8080` never selects the upstream named by `$up`, so it needs a `resolver`.
- `localhost` is exempt only in a literal target, which NGINX resolves at startup through the system resolver. Once the target contains a variable, even just in the path, NGINX resolves the host at request time through `resolver`, and `localhost` counts like any other name.
- For more information about this issue, read [this post](https://joshua.hu/nginx-dns-caching).
