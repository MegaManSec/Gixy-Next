# [proxy_pass_normalized] `proxy_pass` may decode and normalize paths

## What this check looks for

This plugin warns when `proxy_pass` includes a path component, for example `proxy_pass http://backend/api/;` rather than just `proxy_pass http://backend;`.

## Why this is a problem

When a path is present in `proxy_pass`, NGINX performs URI processing before proxying. That can include decoding and normalization steps that change what the upstream sees.

Typical failure modes:

- encoded slashes and dot segments are decoded and normalized (`%2F..%2F` can become `/../`)
- the upstream receives a different path than your access control logic evaluated
- combined with rewrites, you can get double-encoding or surprising path joins

These issues tend to show up as "works in the browser, breaks in production" and in the worst case can turn into traversal/bypass bugs.

## Bad configuration

```
location /api/ {
    # Path included here triggers normalization/decoding behavior
    proxy_pass http://backend/;
}
```

When a user requests `/api/article/..%2F..%2Fuser-uploads%2Fmalicious-file.txt`, the backend will see `user-uploads/malicious-file.txt`.

## Better configuration

If you do not need a fixed prefix, keep proxy_pass host-only:

```
location /api/ {
    proxy_pass http://backend;
}
```

If you do need to add or reshape the path, do it explicitly using captures so you control what is forwarded, use `$request_uri`, and use `return`:

```
location /api/ {
  rewrite ^ $request_uri;
  rewrite ^/api(/.*) $1 break;
  return 400; # extremely important!
  proxy_pass http://backend/$1;
}
```

## Another bad configuration

Make sure you do not go from one bad configuration, to another. This is also a bad configuration:

```
location /1/ {
  rewrite ^ $request_uri;
  rewrite ^/1(/.*) $1 break;
  return 400;
  proxy_pass http://127.0.0.1:8080/
}
```

When a user requests `/1/%2F`, the backend server will see `/%252F`.

## Another better configuration

Here is another example of a good configuration:

```
location /1/ {
  rewrite ^ $request_uri;
  rewrite ^/1(/.*) /special/location$1/folder/ break;
  return 400; # extremely important!
  proxy_pass http://127.0.0.1:8080/$1;
}
```

A request made to `/1/2` will be the the backend server as `/special/location/1/2/folder`.

## Additional notes

Be careful combining `rewrite` with a `proxy_pass` that already has a path. If you are changing the URI, keep it explicit, test with encoded input, and verify what the upstream actually receives. More information can be found in [this post](https://joshua.hu/proxy-pass-nginx-decoding-normalizing-url-path-dangerous).
