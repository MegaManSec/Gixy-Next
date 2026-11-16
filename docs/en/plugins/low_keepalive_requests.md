---
title: "Low Keepalive Requests"
description: "Detects keepalive_requests values that are likely too low for modern traffic patterns (especially HTTP/2), and keep-alive turned off with 0. Low values force frequent connection churn and can cause client-side failures under load."
---

# [low_keepalive_requests] Low `keepalive_requests` value

## What this check looks for

- `keepalive_requests` below 1000.
- `keepalive_requests 0` or `keepalive_timeout 0` (in any unit, such as `0s`), which turn keep-alive off.

## Why this is a problem

`keepalive_requests` controls how many requests a client can send over a single keep-alive connection before NGINX closes it.

Low values create avoidable connection churn:

- With HTTP/2, browsers tend to use fewer connections and multiplex many requests. Closing a connection early forces unnecessary reconnects.
- Some clients will see failed or retried requests when the server closes a busy connection at the wrong time.
- Extra TLS handshakes and TCP setup cost CPU and latency.

In newer NGINX versions, the default is 1000. Older versions historically used 100.

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

If your NGINX already defaults to 1000, you can also omit both directives and keep the defaults.

## Additional notes

The "right" number depends on your traffic and timeouts, but the takeaway is simple: avoid values that force constant reconnecting. If you are tuning performance, look at `keepalive_timeout` and (for upstream keepalive) the `keepalive` directive in `upstream` blocks as well.

This check applies only to the client-facing `keepalive_requests` and `keepalive_timeout` in the `http`, `server`, or `location` context. It does not flag them inside an `upstream {}` block — those are different directives (the limits for cached upstream keep-alive connections, since NGINX 1.15.3), where small values are normal.

On HTTP/3, `keepalive_requests 0` refuses every request and `keepalive_timeout 0` closes connections before they serve one. HTTP/2 and HTTP/3 use the `server`-level values, so a value set in a `location` only affects HTTP/1.x.

In some systems like Burp Proxy, receiving the error "Stream failed to close correctly" indicates that the configuration of the server is using a too-low value of `keepalive_requests`. In mitm-proxy, this error is described as "HTTP/2 protocol error: Invalid ConnectionInputs.RECV_HEADERS in state ConnectionState.CLOSED". If you are unable to change the server configuration, you may also disable HTTP/2 in the browser / proxy. For more information about when this error can show up, read [this post](https://joshua.hu/http2-burp-proxy-mitmproxy-nginx-failing-load-resources-chromium).
