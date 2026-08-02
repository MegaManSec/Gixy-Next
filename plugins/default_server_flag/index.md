# [default_server_flag] Missing `default_server` on shared listen socket

## What this check looks for

This plugin reports when multiple `server` blocks share the same `listen` address and port, but none of them is marked as `default_server` (or `default`).

## Why this is a problem

When an incoming request does not match any `server_name`, NGINX still has to pick a server block. Without an explicit default, selection becomes harder to reason about and may change when configs are refactored or include order changes. That can lead to requests landing on the wrong virtual host, exposing unintended content or certificates.

## Bad configuration

```
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
```

Requests for an unknown hostname will be handled by whichever server ends up being the default implicitly.

## Better configuration

Pick the server you want as the catch-all and mark it explicitly:

```
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

# a.test
server {
    listen 80;
    server_name a.test;

    return 301 https://a.test$request_uri;
}

server {
    listen 443 ssl;
    server_name a.test;

    ssl_certificate     /etc/ssl/a.test.crt;
    ssl_certificate_key /etc/ssl/a.test.key;

    location / { return 200 "a\n"; }
}

# b.test
server {
    listen 80;
    server_name b.test;

    return 301 https://b.test$request_uri;
}

server {
    listen 443 ssl;
    server_name b.test;

    ssl_certificate     /etc/ssl/b.test.crt;
    ssl_certificate_key /etc/ssl/b.test.key;

    location / { return 200 "b\n"; }
}
```

## Additional notes

This plugin only runs when a scan of full configuration is performed, i.e. when the configuration scanned includes an `http { .. }` block.
