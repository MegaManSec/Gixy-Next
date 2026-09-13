# [http_splitting] HTTP splitting (CRLF injection)

## What this check looks for

This plugin looks for cases where user-controlled input can end up inside response headers, usually through `add_header` (or similar) combined with variables that can contain newline characters.

## Why this is a problem

If an attacker can inject `\r\n` into a header value, they can create additional headers or even influence the response body. At a minimum this is a cache poisoning and security header bypass risk, and in the worst case it becomes a response splitting attack against downstream clients.

## Bad configuration

```
# $action comes from a regex capture and is inserted into a response header
location ~ /v1/((?<action>[^.]*)\.json)?$ {
    add_header X-Action $action;
}
```

If the capture allows newlines (directly, or via normalization/decoding elsewhere), an attacker can turn one header into many. For example:

```
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

## Better configuration

1. Prefer safer variables (for example `$request_uri` over `$uri` when you need the raw input).
1. Constrain captures so they cannot contain whitespace or control characters:

```
# Disallow slashes and whitespace in the capture
location ~ ^/some/(?<action>[^/\s]+)$ {
    add_header X-Action $action;
}
```

1. If you must reflect client input, validate it first and keep the allowed character set tight.
