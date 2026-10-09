# [missing_worker_processes] Unset `worker_processes` (defaults to 1)

## What this check looks for

This plugin warns when `worker_processes` is not set anywhere in the config.

## Why this is a problem

`worker_processes` controls how many worker processes NGINX starts to accept and process connections.

When the directive is unset, NGINX defaults to 1. On a multi-core system, a single worker can become a bottleneck:

- Only one worker -- working on a single CPU -- is available to accept and handle connections.
- CPU-bound workloads (TLS, compression, heavy rewrite logic, etc.) can saturate a single core while other cores remain underutilized.
- Under load, this often shows up as higher latency and reduced throughput.

In most cases, running one worker per CPU core works well, and setting `worker_processes` to `auto` is the simplest way to achieve that.

## Bad configuration

```
# No worker_processes directive anywhere
events { }

http {
    server {
        listen 80;
        return 200 "ok\n";
    }
}
```

This will run with the default of a single worker process.

## Better configuration

```
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

This check cannot determine how many CPU cores the host has. On a single-core machine, the default of 1 may be fine, and this warning can be considered a false positive.
