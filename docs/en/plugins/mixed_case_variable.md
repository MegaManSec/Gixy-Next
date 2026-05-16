---
title: "Mixed-case variable references"
description: "Detects when the same NGINX variable is referenced with inconsistent casing within one config. NGINX normalizes all variable names to lowercase, so $My_Var and $MY_VAR are identical — mixing spellings looks like two distinct variables and likely indicates a typo."
---

# [mixed_case_variable] Mixed-case variable references

## What this check looks for

This plugin flags configurations where the same NGINX variable is referenced using more than one casing within the same config — for example, `$My_Var` in one directive and `$MY_VAR` in another.

## Why this is a problem

NGINX normalizes all variable names to lowercase at parse time. `$My_Var`, `$my_var`, and `$MY_VAR` all refer to the same variable. When the same variable appears with different capitalizations in one config, it looks like two distinct variables. This is misleading and almost always indicates a typo — one of the spellings may have been intended to refer to a different variable entirely.

## Bad configuration

```nginx
server {
    location / {
        set $My_Var "hello";
        proxy_pass http://backend/$MY_VAR;
    }
}
```

`$My_Var` and `$MY_VAR` are the same variable; the inconsistency suggests a copy-paste error.

A more subtle case involving conditional logic:

```nginx
server {
    set $jwt_token "";

    if ($http_authorization ~ "^Bearer (.+)$") {
        set $JWT_Token $1;
    }

    if ($jwt_token = "") {
        return 401 "Unauthorized";
    }

    proxy_set_header X-JWT-Token $jwt_token;
}
```

`$jwt_token` and `$JWT_Token` are the same variable — NGINX normalizes both to `jwt_token`. While the code works correctly at runtime, it reads as if two separate variables are in use, hiding the relationship between the initial assignment, the `if`-block update, and the later check. This is confusing and likely masks a typo.

## Better configuration

Use a consistent, lowercase name throughout:

```nginx
server {
    location / {
        set $my_var "hello";
        proxy_pass http://backend/$my_var;
    }
}
```

## Additional notes

This applies to all NGINX variables regardless of origin: user-defined (`set`), built-in (`$http_*`, `$arg_*`, etc.), and variables produced by `map`, `geo`, `rewrite`, and regex capture groups. Named regex capture groups (`(?P<Name>...)`) are also normalized to lowercase by NGINX, so `$Name` and `$name` are the same variable.
