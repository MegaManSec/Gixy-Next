# [proxy_pass_normalized] `proxy_pass` can send an unintended path upstream

## What this check looks for

This plugin reports three ways `proxy_pass` can send the upstream a different path than the one NGINX matched:

- A prefix location and the URI part of `proxy_pass` disagree on a trailing slash: MEDIUM when the location lacks it, LOW when the URI part lacks it.
- The URI is built from the decoded path: `$uri`, `$document_uri`, a regex capture of the path, or a `map` or `set` variable that holds it: MEDIUM.
- `rewrite ^ $request_uri;` sets the URI to the raw path, but `proxy_pass` does not build its URI from variables, so NGINX encodes the raw path again: LOW.

A URI part whose trailing slash matches the location is fine and is not reported, for example `location / { proxy_pass http://127.0.0.1:8080/; }` or `location /api/ { proxy_pass http://127.0.0.1:8080/v2/; }`.

## Why this is a problem

NGINX decodes the request path, resolves `.` and `..` segments and merges `//` before it matches locations; the result is `$uri`. What the upstream receives depends on the `proxy_pass` argument:

- Without a URI part (`proxy_pass http://backend;`), the request URI is sent as the client sent it, unless a `rewrite` changed it.
- With a URI part (`proxy_pass http://backend/v2/;`), the part of `$uri` that matched the location is replaced with the URI part, and the result is percent-encoded again.
- With variables (`proxy_pass http://backend/$1;`), the value is sent as it is, without being encoded again.

## Bad configuration

A location without a trailing slash and a URI part with one:

```
location /api {
    proxy_pass http://backend/v1/;
}
```

Everything after `/api` is appended to `/v1/`. `/api../secret` contains no dot segment, so it matches the location:

- `/api/users` is sent as `/v1//users`
- `/apiusers` is sent as `/v1/users`
- `/api../secret` is sent as `/v1/../secret`, which an upstream that resolves dot segments serves as `/secret`

With `proxy_pass http://backend/;`, `/apiadmin` is sent as `/admin`, past rules such as `location /api/admin { deny all; }`.

The reverse joins the path without a separator: under `location /api/` with `proxy_pass http://backend/v1;`, `/api/users` is sent as `/v1users`.

A regex capture of the decoded path:

```
location ~ ^/img/(.*\.png)$ {
    proxy_pass http://backend/$1;
}
```

`/img/private.json%3F.png` matches the location, and the upstream receives `/private.json?.png`: the path `/private.json` with a query string. `%23` is sent as `#`, and `%20` as a space in the request line. `proxy_pass http://backend$uri;` behaves the same way.

A raw path that is encoded twice:

```
location /1/ {
    rewrite ^ $request_uri;
    rewrite ^/1(/.*) $1 break;
    return 400;
    proxy_pass http://backend;
}
```

`proxy_pass` encodes the raw path again: `/1/%2F` is sent as `/%252F`, and `/1/x?q=1` as `/x%3Fq=1?q=1`.

## Better configuration

Make the location and the URI part agree on the trailing slash:

```
location /api/ {
    proxy_pass http://backend/v1/;
}
```

If the upstream needs the path as the client sent it, leave out the URI part:

```
location /api/ {
    proxy_pass http://backend;
}
```

To strip a prefix and still send the raw path, capture it from `$request_uri` and pass the capture on:

```
location /api/ {
    rewrite ^ $request_uri;
    rewrite ^/api(/.*) $1 break;
    return 400;
    proxy_pass http://backend$1;
}
```

`/api/a%2Fb?q=1` is sent as `/a%2Fb?q=1`. `return 400` rejects requests whose raw path does not start with `/api/`, such as `/foo/../api/x`; without it, NGINX matches the raw path against the locations again, and `/foo/../api/x` is served by `location /foo/`.

## Additional notes

- Even with matching slashes, a URI part changes the path compared to `proxy_pass http://backend;`: `%2F`, `%3B`, `%26` and `%3D` arrive decoded as `/`, `;`, `&` and `=`, `.` and `..` segments are resolved, and `//` is merged. If the upstream needs encoded slashes or the path as the client sent it, leave out the URI part.
- `rewrite ^ $request_uri;` only makes `$uri` and later captures hold the raw path if it always runs before `proxy_pass`. A rewrite inside an `if` block does not count: when the condition is false, they still hold the decoded path.
- Variables are traced to where their value comes from. A capture of `$request_uri`, in `if` or `map`, holds the raw path and is not reported. `set` encodes a numbered capture again when it copies it, so `set $p $1;` is not reported, but `set $p $uri;` and a named capture copied by `set` are. Only a variable that can contain `?`, `#` or `%` is reported, so a `(\d+)` capture or a `map` with fixed values is fine. A variable in the host part also has to be able to contain `/`: `proxy_pass http://backend$1;` with a `(/.*)` capture is reported, `proxy_pass http://$1.internal;` with a `(\w+)` capture is not.
- Exact-match (`=`) locations are not checked. NGINX rejects a URI part without variables in regex and named locations and inside `if` and `limit_except`, so only variables are checked there.
