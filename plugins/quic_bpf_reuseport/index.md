# [quic_bpf_reuseport] QUIC connections silently dropped after reload

## What this check looks for

This plugin flags configurations where all three of the following are present simultaneously:

- `quic_bpf on;` in the main context
- `reuseport` on a QUIC listen socket
- `worker_processes` greater than 1 (or `auto`)

## Why this is a problem

When these conditions coincide, NGINX silently drops approximately 50% of QUIC connections after every `nginx -s reload`. The root cause is stale BPF reuseport maps: after a reload, old worker processes hold BPF maps that reference socket file descriptors which no longer exist in the new workers, so roughly half of incoming QUIC packets are sent to the wrong worker and silently discarded.

This is a known upstream NGINX bug ([nginx/nginx#425](https://github.com/nginx/nginx/issues/425)) that remains unfixed in mainline.

## Bad configuration

```
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

Disable `quic_bpf`:

```
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

- The bug does not trigger with `worker_processes 1` since there is only one worker and no BPF map handoff occurs.
- If `worker_processes` is not set, NGINX defaults to 1, which is also safe.
- Removing `reuseport` from the QUIC listener also avoids the bug, though at the cost of reduced multi-core performance.
