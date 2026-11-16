---
title: "Missing Worker Processes"
description: "Detects configs where worker_processes is unset, which leaves NGINX with a single worker process and limits throughput on multi-core hosts. Set worker_processes to auto."
---

# [missing_worker_processes] Missing `worker_processes`

## What this check looks for

This plugin warns when `worker_processes` is not set at the top level of the configuration.

## Why this is a problem

When `worker_processes` is unset, NGINX starts a single worker, which runs on one CPU. On a multi-core host, CPU-bound work such as TLS and compression saturates that core while the others sit idle, which shows up as higher latency and lower throughput under load.

`worker_processes auto` starts one worker per CPU core, which suits most deployments.

## Bad configuration

```nginx
# No worker_processes directive
events { }

http {
    server {
        listen 80;
        return 200 "ok\n";
    }
}
```

## Better configuration

```nginx
worker_processes auto;

events { }

http {
    server {
        listen 80;
        return 200 "ok\n";
    }
}
```

## Additional notes

- The check only runs on a full configuration, one with a top-level `http` or `events` block.
- The check cannot tell how many CPU cores the host has. On a single-core machine, the default of 1 is fine.
- `auto` counts the host's online CPUs and ignores CPU quotas such as `docker run --cpus` or a Kubernetes CPU limit, so in a CPU-limited container it can start far more workers than can run; set an explicit number there. The official NGINX Docker image does this when `NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE` is set.
