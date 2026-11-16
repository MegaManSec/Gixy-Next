---
title: "Host Header Spoofing"
description: "Detects a proxied Host set from client-controlled values ($http_*, $cookie_*, $arg_*), which can enable phishing, cache poisoning and SSRF. Prefer $host with a strict server_name list."
---

# [host_spoofing] Host header forgery

## What this check looks for

This plugin flags `proxy_set_header Host` and `grpc_set_header Host` (the gRPC `:authority`) when the value comes from the client: any `$http_*` request header such as `$http_host` or `$http_x_forwarded_host`, a `$cookie_*` value, or a query-string `$arg_*`. The value is followed through `set` directives in the same and enclosing blocks and through `map` blocks.

## Why this is a problem

The client chooses these values, and many applications use the host for:

- absolute URL generation (links in emails, redirects),
- tenant selection,
- cache keys.

If the app trusts an attacker-controlled host, you can end up with phishing links, poisoned caches, and in some setups even SSRF-style request routing issues.

## Bad configuration

### host copied from the request

```nginx
location / {
    proxy_set_header Host $http_host;
    proxy_pass http://backend;
}
```

If a client sends `Host: evil.example`, the upstream receives it too.

### host chosen by a map

```nginx
map $http_x_forwarded_host $best_http_host {
    default $http_x_forwarded_host;
    ''      $host;
}

server {
    location / {
        proxy_set_header Host $best_http_host;
        proxy_pass http://backend;
    }
}
```

The `default` entry passes the client's `X-Forwarded-Host` through, so any client that sends that header picks the upstream `Host`.

## Better configuration

Use `$host`, list your names in `server_name`, and keep a separate default server:

```nginx
server {
    listen 80 default_server;
    return 444;
}

server {
    listen 80;
    server_name example.com www.example.com;

    location / {
        proxy_set_header Host $host;
        proxy_pass http://backend;
    }
}
```

A request only reaches the second server when its host name matches a `server_name` entry, so `$host` there is one of those names. In the default server, `$host` is whatever the client sent.

## Additional notes

- A value that also uses `$host`, such as `$host:$http_x_forwarded_port`, is still reported: the client chooses the rest of it.
- A `map` keyed on a client value may pass that value through for an exact name or a `*.example.com` key, since only the listed names get through. A regular expression or (with `hostnames`) an `example.*` key accepts any domain, so such an entry is still reported.
