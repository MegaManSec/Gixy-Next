# [return_bypasses_allow_deny] `return` / redirecting `rewrite` bypass `allow`/`deny`

## What this check looks for

This plugin warns when `return` — or a `rewrite` that emits a redirect — appears in the same context as `allow`/`deny`. A `rewrite` emits a redirect when it carries a `permanent` (301) or `redirect` (302) flag, and also — regardless of flag — when its replacement is an absolute URL starting with `http://`, `https://`, or `$scheme`.

## Why this is a problem

`return` — and a redirecting `rewrite` — run in the rewrite phase and emit a response immediately. Access controls (`allow`/`deny`) are evaluated later, in the access phase. That means such a directive placed next to access rules can effectively ignore them, even if the config looks like it should be restricted. (A `rewrite ... last` or `rewrite ... break` whose replacement is a plain URI keeps processing toward the access phase, so it is *not* flagged. With an absolute-URL replacement, however, NGINX redirects immediately even under `last` or `break`.)

In other words: the block reads like "allow X, deny everyone else", but the request never actually reaches the access phase: it simply returns unconditionally.

## Bad configuration

```
location /admin/ {
    allow 127.0.0.1;
    deny all;

    # This is evaluated before the access rules above
    return 200 "hi";
}
```

The response is served to everyone, including clients you intended to deny. The same happens if you replace the `return` with `rewrite ^ https://example.test/ permanent;`, or even a flagless `rewrite ^ https://example.test$request_uri;` — the redirect is issued before the access phase.

## Better configuration

`return` always runs in the rewrite phase, so no arrangement of locations makes `allow`/`deny` apply to it. Serve the response from the **content** phase instead — `try_files`, `proxy_pass`, `root`/`index` — because the content phase runs after the access phase:

```
location /admin/ {
    allow 127.0.0.1;
    deny all;

    root /var/www/admin;
    try_files /index.html =404;
}
```

Or, when the response comes from an upstream:

```
location /admin/ {
    allow 127.0.0.1;
    deny all;

    proxy_pass http://admin_backend;
}
```

Both answer `403` to a denied client.

## What does not work

Moving the `return` into a named location does **not** help. A named location cannot be requested directly, but reaching it through `error_page` does not re-run the access phase, and the `return` inside it still fires during the rewrite phase:

```
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

A denied client receives `200` and the body. This is why the check still reports a `return` that sits beside `allow`/`deny` in a named or `internal` location.

Guarding the `return` with `auth_basic` or `auth_request` fails for the same reason: those are access-phase modules too, so the `return` is emitted before they run.

## Additional notes

If your goal is simply "block everyone but X", `allow X; deny all;` is enough on its own — a denied client already gets `403`, so no `return` is needed. Add a content-phase handler for the clients you do allow.

For more information about this issue, see [this post](https://joshua.hu/nginx-return-allow-deny).
