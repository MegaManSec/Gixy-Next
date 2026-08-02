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

If you need to return a response and still enforce allow/deny, move the return into a separate internal handler and put the access rules there:

```
location /admin/ {
    # Always internally redirect to a named location
    error_page 418 = @admin_handler;
    return 418;
}

location @admin_handler {
    allow 127.0.0.1;
    deny all;

    return 200 "hi";
}
```

Named locations cannot be requested directly by clients, so you can safely concentrate the access rules and the response logic there.

## Additional notes

If your goal is simply "block everyone but X", prefer expressing it as access control only (for example return 403/444 for everyone else) rather than combining allow/deny with unconditional returns in the same block.

For more information about this issue, see [this post](https://joshua.hu/nginx-return-allow-deny).
