# [worker_rlimit_nofile_vs_connections] `worker_rlimit_nofile` must be at least twice `worker_connections`

## What this check looks for

This plugin checks the relationship between `worker_connections` and `worker_rlimit_nofile` and warns when the file descriptor limit is too low.

If `worker_connections` is unset, the default is used: 512.

If `worker_rlimit_nofile` is unset, an estimate of the default (most likely for major Linux distributions) is used: 512.

## Why this is a problem

NGINX needs file descriptors (FDs) for more than just client connections.

Typical FD usage:

- Web server mode: 1 FD for the client connection, plus at least 1 FD for the file being served. A single page load can involve multiple files.
- Proxy mode: 1 FD for the client connection and 1 FD for the upstream connection, plus potentially a temporary file.
- Caching mode: combines both behaviors (serve cached files, and proxy/cache misses).

If the FD limit is too low, workers will start failing with "Too many open files", which shows up as request failures under load.

## Bad configuration

```
worker_connections 4096;
# Missing or too-low worker_rlimit_nofile
```

or:

```
worker_connections 4096;
worker_rlimit_nofile 4096;
```

A 1:1 ratio is often not enough once you account for upstream sockets and files.

## Better configuration

A practical baseline is at least 2x worker_connections:

```
worker_connections 4096;
worker_rlimit_nofile 8192;
```

Adjust upward if you are proxying heavily, caching, or serving lots of static assets.

## Additional notes

Also check the OS-level limits (ulimit, systemd unit limits, container limits). Setting `worker_rlimit_nofile` higher than the process is allowed to use will not help. The common idiom is:

```
max clients = worker_processes * worker_connections
```
