# [proxy_buffering_off] Disabling `proxy_buffering`

## What this check looks for

This plugin looks for `proxy_buffering` directives that are explicitly set to `off`.

## Why this is a problem

When `proxy_buffering` is disabled, NGINX streams the upstream response directly to the client. That means a slow client can keep an upstream connection and NGINX worker resources occupied for longer than necessary, increasing the risk of slow-client (bandwidth-drip) DoS and upstream backpressure issues.

## Bad configuration

```
location /api/ {
    proxy_pass http://upstream;
    proxy_buffering off;
}
```

## Better configuration

```
location /api/ {
    proxy_pass http://upstream;
    proxy_buffering on;
}
```

Buffering lets NGINX absorb differences between upstream speed and client speed, reducing resource pressure.

## Safe exception

If you are intentionally streaming (for example SSE, long polling, or large downloads) and you need low-latency forwarding, disabling buffering can be appropriate. When you do, apply tight timeouts and limits:

```
location /events/ {
    proxy_pass http://upstream;
    proxy_buffering off;

    # Add guardrails so slow clients do not hold resources forever
    send_timeout 10s;
    proxy_read_timeout 60s;
}
```
