# [add_header_multiline] Multiline response headers

## What this check looks for

This plugin flags response headers that contain a literal newline in the header value. The usual culprits are `add_header`, `more_set_headers`, or string values that span multiple lines for readability.

## Why this is a problem

Multiline headers are deprecated and not reliably supported by clients. Some browsers and HTTP stacks will reject or truncate the response, and some intermediaries can mis-parse the header stream. In practice, this turns into hard-to-debug compatibility issues.

## Bad configuration

```
# Multiline header value (contains a newline)
more_set_headers 'X-Foo: Bar
  multiline';
```

Even if it "works" in a quick test, it is not safe to rely on.

```
add_header 'Access-Control-Allow-Headers' 'Content-Disposition,Content-Range,DNT,X-CustomHeader,Keep-Alive,
User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type';
```

This is also an unsafe usage, which may result in the header being completely cut off.

## Better configuration

Keep the configuration readable, but make the actual header value a single line by composing it with variables.

Option 1: build the value from separate pieces:

```
set $csp_default "default-src 'self'";
set $csp_script  "script-src 'self' https://cdn.example.com";
set $csp_style   "style-src 'self' https://cdn.example.com";
set $csp_img     "img-src 'self' data: https://cdn.example.com";
set $csp_font    "font-src 'self' https://cdn.example.com";

set $csp "${csp_default}; ${csp_script}; ${csp_style}; ${csp_img}; ${csp_font}";
add_header Content-Security-Policy $csp;
```

Option 2: progressive concatenation:

```
set $csp "default-src 'self'; ";
set $csp "${csp}script-src 'self' https://cdn.example.com; ";
set $csp "${csp}style-src 'self' https://cdn.example.com; ";
set $csp "${csp}img-src 'self' data: https://cdn.example.com; ";
set $csp "${csp}font-src 'self'";

add_header Content-Security-Policy $csp;
```
