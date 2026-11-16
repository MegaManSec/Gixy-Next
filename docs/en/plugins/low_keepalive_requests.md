---
title: "Low Keepalive Requests"
description: "Detects keepalive_requests values that are likely too low for modern traffic patterns (especially HTTP/2), and keep-alive turned off with 0. Low values force frequent connection churn and can cause client-side failures under load."
---

# [low_keepalive_requests] Low `keepalive_requests`

## What this check looks for

- `keepalive_requests` below 1000.
- `keepalive_requests 0` or `keepalive_timeout 0` (in any unit, such as `0s`), which turn keep-alive off.

## Why this is a problem

`keepalive_requests` controls how many requests a client can send over a single keep-alive connection before NGINX closes it. The default is 1000.

Low values create avoidable connection churn:

- With HTTP/2, browsers tend to use fewer connections and multiplex many requests. Closing a connection early forces unnecessary reconnects.
- Some clients will see failed or retried requests when the server closes a busy connection at the wrong time.
- Extra TLS handshakes and TCP setup cost CPU and latency.

## Bad configuration

### low request limit

```nginx
keepalive_requests 100;
```

This is often too low for modern browsers and HTTP/2 workloads.

### keep-alive disabled

```nginx
keepalive_timeout 0;
```

Every connection is closed after its first request.

## Better configuration

```nginx
keepalive_requests 1000;
keepalive_timeout 75s;
```

These are the defaults, so leaving both directives out works as well.

## Additional notes

- Only the client-facing directives in the `http`, `server` and `location` contexts are checked. `keepalive_requests` and `keepalive_timeout` inside an `upstream` block are different directives (limits for cached upstream connections, NGINX 1.15.3+) where small values are normal, so they are not reported.
- HTTP/2 and HTTP/3 use the `server`-level values, so a value set in a `location` only affects HTTP/1.x. On HTTP/3, `keepalive_requests 0` refuses every request and `keepalive_timeout 0` closes connections before they serve one.
- In Burp Proxy, a too-low `keepalive_requests` shows up as "Stream failed to close correctly"; in mitmproxy as "HTTP/2 protocol error: Invalid ConnectionInputs.RECV_HEADERS in state ConnectionState.CLOSED". If you cannot change the server, disable HTTP/2 in the browser or proxy. For more information, read [this post](https://joshua.hu/http2-burp-proxy-mitmproxy-nginx-failing-load-resources-chromium).
