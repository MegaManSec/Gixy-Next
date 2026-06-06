---
title: "Low Keepalive Requests"
description: "Detects keepalive_requests values that are likely too low for modern traffic patterns (especially HTTP/2). Low values force frequent connection churn and can cause client-side failures under load."
---

# [low_keepalive_requests] Low `keepalive_requests` value

## What this check looks for

This plugin warns when `keepalive_requests` is set to an unusually low number.

## Why this is a problem

`keepalive_requests` controls how many requests a client can send over a single keep-alive connection before NGINX closes it.

Low values create avoidable connection churn:

- With HTTP/2, browsers tend to use fewer connections and multiplex many requests. Closing a connection early forces unnecessary reconnects.
- Some clients will see failed or retried requests when the server closes a busy connection at the wrong time.
- Extra TLS handshakes and TCP setup cost CPU and latency.

In newer NGINX versions, the default is 1000. Older versions historically used 100.

## Bad configuration

```nginx
keepalive_requests 100;
```

This is often too low for modern browsers and HTTP/2 workloads.

## Better configuration

```nginx
keepalive_requests 1000;
```

If your NGINX already defaults to 1000, you can also omit the directive and keep the defaults.

## Additional notes

The "right" number depends on your traffic and timeouts, but the takeaway is simple: avoid values that force constant reconnecting. If you are tuning performance, look at `keepalive_timeout` and (for upstream keepalive) the `keepalive` directive in `upstream` blocks as well.

This check applies only to the client-facing `keepalive_requests` in the `http`, `server`, or `location` context. It does not flag `keepalive_requests` inside an `upstream {}` block — that is a different directive (the maximum number of requests per upstream keep-alive connection, since NGINX 1.15.3), where small values are normal.

`keepalive_requests 0` is flagged. NGINX tests the per-connection request count with `requests >= keepalive_requests` and applies no special case for `0`, so a value of `0` makes the condition always true: the connection is closed after every request and client keep-alive is disabled entirely — the most aggressive form of the connection churn this check warns about.

In some systems like Burp Proxy, receiving the error "Stream failed to close correctly" indicates that the configuration of the server is using a too-low value of `keepalive_requests`. In mitm-proxy, this error is described as "HTTP/2 protocol error: Invalid ConnectionInputs.RECV_HEADERS in state ConnectionState.CLOSED". If you are unable to change the server configuration, you may also disable HTTP/2 in the browser / proxy. For more information about when this error can show up, read [this post](https://joshua.hu/http2-burp-proxy-mitmproxy-nginx-failing-load-resources-chromium).
