---
title: "QUIC BPF Reuseport"
description: "Detects quic_bpf on with reuseport and several workers, which drops about half of new QUIC connections after every reload on NGINX before 1.31.7."
---

# [quic_bpf_reuseport] QUIC connections silently dropped after reload

## What this check looks for

This plugin flags configurations where all of the following are true:

- `quic_bpf on;` in the main context
- `reuseport` on a QUIC `listen` socket
- `worker_processes` greater than 1 (or `auto`)

## Why this is a problem

On NGINX before 1.31.7, these settings make NGINX silently drop about half of new QUIC connections after every `nginx -s reload`: the BPF reuseport maps still point at the old workers' sockets, so packets reach the wrong worker.

This was upstream bug [nginx/nginx#425](https://github.com/nginx/nginx/issues/425), fixed in mainline 1.31.7 by [nginx/nginx#1756](https://github.com/nginx/nginx/pull/1756). No stable release up to 1.30.x has the fix.

## Bad configuration

```nginx
worker_processes auto;
quic_bpf on;

http {
    server {
        listen 443 quic reuseport;
        listen 443 ssl;
        server_name example.com;
    }
}
```

## Better configuration

Upgrade to NGINX 1.31.7 or later, or disable `quic_bpf`:

```nginx
worker_processes auto;
quic_bpf off;

http {
    server {
        listen 443 quic reuseport;
        listen 443 ssl;
        server_name example.com;
    }
}
```

## Additional notes

- Gixy-Next cannot see the NGINX version. On 1.31.7 or later the finding does not apply; skip it with `--skips quic_bpf_reuseport`.
- `worker_processes 1`, the default, is not affected.
- Do not remove `reuseport` instead: without it, several workers read one UDP socket, a connection's packets can reach a worker that does not know it, and QUIC handshakes fail even without a reload.
