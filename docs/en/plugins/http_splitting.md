---
title: "HTTP Response Splitting"
description: "Detects patterns that allow CRLF injection into response or upstream request headers (HTTP splitting). Typically caused by unsafe variables in add_header or proxy_set_header, or unbounded regex captures."
---

# [http_splitting] HTTP splitting (CRLF injection)

## What this check looks for

This plugin looks for cases where user-controlled input can end up inside response headers (`add_header`, `return`, `rewrite`) or inside the request NGINX sends upstream (`proxy_set_header`, `proxy_pass`), through variables that can contain newline characters:

- regex captures that are not restricted to a safe character set,
- `$uri` and `$document_uri`, which hold the decoded URI, so `%0d%0a` becomes a line break,
- `$request_body`, which is raw client input,
- `$remote_user`, which NGINX base64-decodes from the `Authorization` header without validation.

## Why this is a problem

If an attacker can inject `\r\n` into a header value, they can create additional headers or even influence the response body. At a minimum this is a cache poisoning and security header bypass risk, and in the worst case it becomes a response splitting attack against downstream clients.

## Bad configuration

### regex capture in a response header

```nginx
# $action comes from a regex capture and is inserted into a response header
location ~ /v1/((?<action>[^.]*)\.json)?$ {
    add_header X-Action $action;
}
```

If the capture allows newlines (directly, or via normalization/decoding elsewhere), an attacker can turn one header into many. For example:

```http
GET /v1/see%20below%0d%0ax-crlf-header:injected.json HTTP/1.0
Host: localhost

HTTP/1.1 200 OK
Server: nginx/1.11.10
Date: Mon, 13 Mar 2017 21:21:29 GMT
Content-Type: application/octet-stream
Content-Length: 2
Connection: close
X-Action: see below
x-crlf-header:injected

OK
```

### remote_user forwarded to the upstream

```nginx
location / {
    proxy_set_header X-User $remote_user;
    proxy_pass http://backend;
}
```

`$remote_user` is the part before the first `:` of the base64-decoded `Authorization: Basic` header, and NGINX sets it for every request that carries that header, authenticated or not. Base64 can encode any byte, so a client can put `\r\n` into the user name and add headers of its own to the request that reaches the backend.

## Better configuration

1. Prefer safer variables (for example `$request_uri` over `$uri` when you need the raw input).

2. Constrain captures so they cannot contain whitespace or control characters:

   ```nginx
   # Disallow slashes and whitespace in the capture
   location ~ ^/some/(?<action>[^/\s]+)$ {
       add_header X-Action $action;
   }
   ```

3. If you must reflect client input, validate it first and keep the allowed character set tight.

4. Only forward `$remote_user` from a scope where Basic authentication is actually enforced:

   ```nginx
   location / {
       auth_basic           "Restricted";
       auth_basic_user_file /etc/nginx/htpasswd;
       proxy_set_header     X-User $remote_user;
       proxy_pass           http://backend;
   }
   ```

## Additional notes

- `$remote_user` is not reported when `auth_basic` (not `off`) and `auth_basic_user_file` are both in effect for the directive and `satisfy` is `all` (the default). The user name then has to match an entry in the password file before the request is proxied or answered. With `satisfy any`, clients that pass another access check skip the password check, so the finding stays; without `auth_basic_user_file` the module does not enforce anything.
- `$request` (the request line) and `$content_type` (the request `Content-Type` header) are client-controlled but cannot contain line breaks, so they are not reported here.
