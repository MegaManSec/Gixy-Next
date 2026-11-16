---
title: "External DNS Resolvers"
description: "Detects resolver directives pointing to public DNS servers. Using external resolvers can expose you to spoofing and cache poisoning, especially when proxy_pass uses variables."
---

# [resolver_external] Using external DNS nameservers

## What this check looks for

This plugin warns when the `resolver` directive points to a nameserver outside your network instead of a trusted local resolver:

- a public IP address, for example `1.1.1.1` or `8.8.8.8`
- a hostname under a public suffix, for example `dns.google`

## Why this is a problem

NGINX caches the answers its resolver gets at request time. The resolver sends every query from one long-lived UDP socket, so the only thing an off-path attacker has to guess is a 16-bit query ID. An attacker who can trigger lookups, for example through a `proxy_pass` with variables, can race spoofed answers into the cache and redirect traffic. Spoofing a loopback or private nameserver from outside is much harder.

Various vulnerabilities have been [discovered](https://web.archive.org/web/20250317201620/https://blog.zorinaq.com/nginx-resolver-vulns/) in Nginx's dns resolver, with some of them still unfixed.

## Bad configuration

```nginx
# Public resolvers
resolver 1.1.1.1 8.8.8.8;
```

## Better configuration

Use a local resolver on loopback that you control (dnsmasq, unbound, systemd-resolved, etc.):

```nginx
resolver 127.0.0.1 [::1] valid=10s;
resolver_timeout 5s;
```

## Additional notes

- Loopback, private, link-local and shared (`100.64.0.0/10`, used by Tailscale's `100.100.100.100`) addresses are not reported. An IPv4-mapped address such as `[::ffff:10.0.0.1]` is judged by its IPv4 address.
- Hostnames without a public suffix, such as `localhost` or `dns.internal`, are not reported.
