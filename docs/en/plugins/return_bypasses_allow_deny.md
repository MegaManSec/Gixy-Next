---
title: "Return Bypasses Allow/Deny"
description: "Detects return and redirecting rewrite directives next to allow/deny or an auth module. They respond in the rewrite phase, before access control runs."
---

# [return_bypasses_allow_deny] `return` / redirecting `rewrite` bypass `allow`/`deny`

## What this check looks for

This plugin warns when `return`, or a `rewrite` that redirects, is in a context restricted by `allow`/`deny` or by `auth_basic`, `auth_request`, `auth_jwt` or `auth_oidc`, or in a context below it that inherits the restriction. A `rewrite` redirects when it has the `permanent` or `redirect` flag, or when its replacement starts with `http://`, `https://` or `$scheme`, whatever its flag.

It does not report:

- `allow` rules without a `deny`, or, in a file with an `http` block, `auth_basic` without an `auth_basic_user_file`, since neither stops anyone;
- a `location` with its own `allow`/`deny` or auth directive, which replaces the inherited one;
- a bodyless error `return`, such as `return 404;`, unless an `error_page` in effect lists the status and a denied client would get a different one (`403` from `deny`, `401` from `auth_basic` or `auth_jwt`, `401` or `403` from `auth_request`);
- `stream` servers, where `return` runs after the access checks.

## Why this is a problem

`return` and a redirecting `rewrite` respond in the rewrite phase, before the access phase where `allow`/`deny` and the auth modules run. The block reads like "allow X, deny everyone else", but everyone gets the response.

## Bad configuration

### return beside allow/deny

```nginx
location /admin/ {
    allow 127.0.0.1;
    deny all;

    # This is evaluated before the access rules above
    return 200 "hi";
}
```

### return beside auth_basic

```nginx
location /admin/ {
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/htpasswd;

    return 200 "hi";
}
```

A client without credentials receives `200` and the body.

### return in a named location

Moving the `return` into a named location does **not** help: NGINX runs its access phase only after its rewrite phase, where the `return` has already responded.

```nginx
location /admin/ {
    error_page 418 = @admin_handler;
    return 418;
}

location @admin_handler {
    allow 127.0.0.1;
    deny all;

    return 200 "hi";   # served to everyone
}
```

## Better configuration

Serve the response from the content phase, which runs after the access phase: `try_files`, `root`/`index` or `proxy_pass`.

```nginx
location /admin/ {
    allow 127.0.0.1;
    deny all;

    root /var/www/admin;
    try_files /index.html =404;
}
```

## How severity is determined

- **HIGH**: a bypassing directive serves content, such as `return 200 "...";`.
- **LOW**: every bypassing directive is a redirect, such as `return 301 https://$host$request_uri;`, or a `return` below `400` without body text, such as a CORS preflight `return 204;`.

## Additional notes

To block everyone but X, `allow X; deny all;` is enough on its own: a denied client already gets `403`.

For more information about this issue, see [this post](https://joshua.hu/nginx-return-allow-deny).
