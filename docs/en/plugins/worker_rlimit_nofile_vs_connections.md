---
title: "Low worker_rlimit_nofile"
description: "Detects worker_rlimit_nofile values that are too low relative to worker_connections. If the file descriptor limit is not high enough, workers can hit 'Too many open files' under load."
---

# [worker_rlimit_nofile_vs_connections] `worker_rlimit_nofile` must be at least twice `worker_connections`

## What this check looks for

- `worker_rlimit_nofile` set below twice `worker_connections` (default 512).
- `worker_rlimit_nofile` unset while `worker_connections` is above 512. The inherited limit is not in the config, so the check assumes the common 1024.

## Why this is a problem

NGINX needs file descriptors (FDs) for more than its connections. `worker_connections` already caps every socket a worker holds, upstream connections included, so the FDs beyond it go to files:

- Web server mode: the file each request serves.
- Proxy mode: a temporary file for a response buffered to disk.
- Caching mode: the cached file on a hit, and proxy mode on a miss.
- HTTP/2 and `open_file_cache`: many open files per connection, or files kept open after their requests finish.

If the FD limit is too low, workers fail with "Too many open files", which shows up as request failures under load.

## Bad configuration

### missing worker_rlimit_nofile

```nginx
events {
    worker_connections 4096;
}
```

### 1:1 ratio

```nginx
worker_rlimit_nofile 4096;

events {
    worker_connections 4096;
}
```

A 1:1 ratio leaves no room for the files that requests hold open.

## Better configuration

A practical baseline is at least 2x `worker_connections`:

```nginx
worker_processes auto;
worker_rlimit_nofile 8192;

events {
    worker_connections 4096;
}
```

Adjust upward if you are proxying heavily, caching, serving lots of static assets, or using HTTP/2 or `open_file_cache`.

## How severity is determined

- **MEDIUM**: `worker_rlimit_nofile` is set too low. NGINX also makes it the workers' hard limit, so the shortfall is certain.
- **LOW**: `worker_rlimit_nofile` is not set. The real limit comes from the service manager or container and may be high enough.

## Additional notes

- Without `worker_rlimit_nofile`, workers inherit the limit from `ulimit`, the systemd unit's `LimitNOFILE` or the container runtime; check it in `/proc/<worker pid>/limits`.
- Raising `worker_rlimit_nofile` above the inherited hard limit needs `CAP_SYS_RESOURCE`, which a default Docker container does not have.
- A worker serves at most `worker_connections` clients, or half that when every request also opens an upstream connection, so `worker_processes * worker_connections` is the usual capacity estimate.
