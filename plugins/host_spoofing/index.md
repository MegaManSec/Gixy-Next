# [host_spoofing] Host header forgery

## What this check looks for

This plugin flags configurations that set the `Host` from a client-controlled value — `$http_host`, `$http_x_forwarded_host` (the `X-Forwarded-Host` request header), a `$cookie_*` value, or a query-string `$arg_*` — especially when it is passed upstream or used to build redirects/URLs.

## Why this is a problem

`$http_host` comes directly from the client. Attackers can spoof it, and many applications use the host value for:

- absolute URL generation (links in emails, redirects),
- tenant selection,
- cache keys.

If the app trusts an attacker-controlled host, you can end up with phishing links, poisoned caches, and in some setups even SSRF-style request routing issues.

## Bad configuration

```
location / {
    proxy_set_header Host $http_host;
    proxy_pass http://backend;
}
```

If a client sends `Host: evil.example`, the upstream receives it too.

## Better configuration

Use `$host`, and make sure your `server_name` is strict:

```
server {
    listen 80 default_server;
    server_name example.com www.example.com;

    location / {
        proxy_set_header Host $host;
        proxy_pass http://backend;
    }
}
```

`$host` is normalized by NGINX and tied into virtual host selection.

## Additional notes

In general, apply the same rule to any client-controlled value used as the host — `$http_*` request headers (such as `$http_x_forwarded_host`), `$cookie_*`, and `$arg_*`: they should all be considered untrusted. Only `$host` is normalized by NGINX and tied to `server_name` selection.
