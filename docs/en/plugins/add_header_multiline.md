---
title: "Multiline Headers"
description: "Detects header values that contain a line break. NGINX sends the value as it is, which breaks clients and upstreams; use variables to keep long values readable."
---

# [add_header_multiline] Multiline headers

## What this check looks for

This plugin flags header values that contain a newline (including obsolete line folding) or a carriage return, whether the value is written across several lines or uses the `\n` and `\r` escapes.

It checks `add_header`, `add_trailer` and `more_set_headers`, and the request headers sent upstream with `proxy_set_header`, `grpc_set_header` and `more_set_input_headers`.

## Why this is a problem

A header value must not contain CR or LF (RFC 9110), and NGINX sends it as it is. Over HTTP/1.1 the line break ends the header, so the rest of the value goes out as a header line of its own, which clients drop or reject; a value that ends with a line break ends the header block, and every later header lands in the body. Over HTTP/2 the field is invalid. An upstream receives the same split request header, and a gRPC upstream rejects the request with 400.

## Bad configuration

```nginx
add_header 'Access-Control-Allow-Headers' 'Content-Disposition,Content-Range,DNT,X-CustomHeader,Keep-Alive,
User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type';
```

The header ends at `Keep-Alive,`; the second line goes out as a header line without a colon, so the client never sees the rest of the list.

## Better configuration

Keep the configuration readable, but make the actual header value a single line by composing it with variables:

```nginx
set $csp_default "default-src 'self'";
set $csp_script  "script-src 'self' https://cdn.example.com";
set $csp_style   "style-src 'self' https://cdn.example.com";

set $csp "${csp_default}; ${csp_script}; ${csp_style}";
add_header Content-Security-Policy $csp;
```

## Additional notes

- A line break that arrives through a variable, such as `add_header X-Path $uri;`, is reported by [http_splitting](http_splitting.md) instead.
- `fastcgi_param`, `uwsgi_param` and `scgi_param` are not checked: those protocols send length-prefixed values, so a line break cannot end a header.
