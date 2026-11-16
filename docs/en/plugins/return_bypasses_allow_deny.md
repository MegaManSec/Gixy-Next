---
title: "Return Bypasses Allow/Deny"
description: "Detects return and redirecting rewrite directives next to allow/deny or an auth module. They respond in the rewrite phase, before access control runs."
---

# [return_bypasses_allow_deny] `return` bypasses `allow`/`deny` and the auth modules

## What this check looks for

This plugin warns when `return`, or a `rewrite` that redirects, is in a context restricted by `allow`/`deny`, `auth_basic`, `auth_request`, `auth_jwt` or `auth_oidc`, or in a context below it that inherits the restriction. A `rewrite` redirects when it has the `permanent` or `redirect` flag, or when its replacement starts with `http://`, `https://` or `$scheme`, whatever its flag.

It does not report:

- `allow` rules without a `deny`, or, in a file with an `http` block, `auth_basic` without an `auth_basic_user_file`, since neither stops anyone;
- an inherited restriction in a `location` that declares its own `allow`/`deny` or the same auth directive: the location's own rules replace it and are checked instead;
- an inherited restriction in a named location, or in an `internal` location no `rewrite` leads to: `try_files` and `error_page` enter them only after the originating location's access phase. A `rewrite ... last`, a flagless `rewrite`, or any `rewrite` at `server` level whose replacement can match an `internal` location enters it before any access phase, so that location is checked like any other;
- an auth module under `satisfy any` when `allow all` is in effect, since the auth modules then never run;
- a `return` of an error status without body text, such as `return 404;`, which only produces NGINX's error page. It is reported when an `error_page` in effect lists the status, unless that status is the one the restriction answers with anyway: `403` for `deny`, `401` for `auth_basic` and `auth_jwt`, `401` or `403` for `auth_request`;
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

Moving the `return` into a named location does **not** help: the named location's access phase also runs after its rewrite phase, where the `return` has already responded.

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

A CORS preflight such as `if ($request_method = OPTIONS) { return 204; }` under an auth module is reported at LOW. Browsers send preflights without credentials, so that bypass is usually intended.

For more information about this issue, see [this post](https://joshua.hu/nginx-return-allow-deny).
