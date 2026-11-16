---
title: "Mixed-Case Variable References"
description: "Detects the same NGINX variable written with different casing in one configuration; NGINX lowercases variable names, so the spellings are one variable and the mix usually hides a typo."
---

# [mixed_case_variable] Mixed-case variable references

## What this check looks for

This plugin flags the same variable referenced with more than one casing in one configuration, for example `$My_Var` in one directive and `$MY_VAR` in another.

## Why this is a problem

NGINX lowercases variable names when it reads the configuration, so `$My_Var`, `$my_var` and `$MY_VAR` are one variable. Written with different casings they look like two, which hides what the configuration does and usually means one spelling was meant to be a different variable.

## Bad configuration

```nginx
server {
    location / {
        set $My_Var "hello";
        proxy_pass http://backend/$MY_VAR;
    }
}
```

`$My_Var` and `$MY_VAR` are the same variable.

## Better configuration

Use one lowercase spelling throughout:

```nginx
server {
    location / {
        set $my_var "hello";
        proxy_pass http://backend/$my_var;
    }
}
```

## Additional notes

- This applies to every variable: those defined with `set`, `map` and `geo`, built-in ones such as `$http_*` and `$arg_*`, and named captures. A capture `(?<Name>...)` is lowercased too, so `$Name` and `$name` are the same variable.
- The regular expressions of `location ~`, `if (... ~ ...)`, `rewrite` and `server_name ~` are not checked: there `$Name` is an end-of-string anchor followed by `Name`, and `\$Name` a literal dollar sign. In a value, `"\$Name"` still references `$name`, because the backslash does not escape `$`.
