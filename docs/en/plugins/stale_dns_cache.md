---
title: "Outdated/stale cached DNS records used in proxy_pass"
description: "Detects proxy_pass targets whose hostnames are resolved only at startup, so the cached IP addresses can go stale. Use a variable with a resolver, or upstream server ... resolve."
---

# [stale_dns_cache] Outdated/stale cached DNS records used in proxy_pass

## What this check looks for

This plugin reports hostnames that NGINX resolves only once, at startup, so requests can go to outdated IP addresses:

- `proxy_pass` points at a literal hostname, for example `proxy_pass https://api.example.com;`,
- `proxy_pass` points to an `upstream`, and one or more `server` entries inside that `upstream` are hostnames without the `resolve` option.

`fastcgi_pass`, `uwsgi_pass`, `scgi_pass` and `grpc_pass` are checked the same way.

## Why this is a problem

By default, NGINX resolves upstream hostnames once at startup and ignores their TTL. When the records change, traffic keeps going to the old addresses, which may now belong to another host.

If you want NGINX to re-resolve names at runtime, you have to opt into it using either:

- variables in `proxy_pass` plus a configured `resolver`, or
- `upstream` servers with the `resolve` parameter plus a configured `resolver` and a shared `zone` (available in NGINX Open Source starting 1.27.3; previously NGINX Plus only).

## Bad configuration

### static hostname in proxy_pass

```nginx
location / {
    proxy_pass https://api.example.com;
}
```

NGINX resolves the name on startup and keeps the addresses until reload or restart.

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

Without a `resolver`, this proxy does not work at all. A variable whose values are all unix sockets or IP addresses, such as a `map` that picks a PHP-FPM socket, needs no `resolver` and is not reported.

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

Here NGINX does not even start or reload: `server ... resolve` needs a `resolver`, and without one `nginx -t` fails with "no resolver defined to resolve names at run time".

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

With any variable in `proxy_pass`, NGINX resolves the name at request time through the `resolver`, which must be set. It honors the record's TTL unless `valid=` overrides it.

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

Since NGINX 1.27.3, `server ... resolve` re-resolves upstream names the same way, and also needs a `resolver`.

## How severity is determined

This plugin uses different severities depending on what it finds. Concretely:

- If the flagged `proxy_pass` target (or `upstream server`) is a hostname without a registrable suffix (for example, internal names like `backend` or `service.namespace`), the issue is reported as LOW.
- If the flagged target is a hostname with a registrable suffix (for example, `api.example.com`), the issue is reported as MEDIUM, because these names are commonly backed by load balancers / CDNs and are more likely to change over time.
- If the configuration is attempting runtime re-resolution (`proxy_pass` with variables, or `upstream ... resolve`) but no `resolver` is configured, the proxying will not work at all, and the issue is reported as MEDIUM.

## Additional notes

For more information about this issue, read [this post](https://joshua.hu/nginx-dns-caching).
