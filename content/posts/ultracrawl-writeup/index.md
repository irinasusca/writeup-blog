+++
date = '2026-01-26'
draft = false
title = 'CyberEdu ultra-crawl Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

## Challenge overview

Here is your favorite proxy for crawling minimal websites.

## Identifying the vulnerabilities

This looks like some sort of crawler that mirrors the given page's response. After a pipedream webhook, looks like they're using `Python-urllib/3.6`.

Some classic SSRF, we can just feed this crawler a `file:///etc/passwd` and surprise, it works! 

![challenge-screenshot](etc.png#center)

Now we just need to figure our where our flag is - if we input a wrong file location, we get a 500. From /etc/passwd, looks like we have a /home/ctf user, so let's look for the flag there.

After trying a TON of locations, I found the text `python3app.py` in `/proc/self/cmdline`. This means something ran `python3 app.py`. So in `file:///home/ctf/app.py`, we find 

```python
import base64 
from urllib.request import urlopen 
from flask import Flask, render_template, request
app = Flask(__name__) @app.route('/', methods=['GET', 'POST']) def index(): print(request.headers['Host']) 
if request.headers['Host'] == "company.tld": 
    flag = open('sir-a-random-folder-for-the-flag/flag.txt').read() 
    return flag 
if request.method == 'POST': 
    url = request.form.get('url') 
    output = urlopen(url).read().decode('utf-8') 
    if base64.b64decode("Y3Rmew==").decode('utf-8') in output: 
        return "nope! try harder!"
    return output 
else: 
    return render_template("index.html") 
if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_evalex=False)
```

Trying to access `file:///home/ctf/sir-a-random-folder-for-the-flag/flag.txt` gives us that *try harder*. The `Y3Rmew==` they're blocking is b64 for `ctf{`. We can get over this by having it send a header - `Host: company.tld`. 

The version of `urllib` being used is vulnerable to **CRLF**. What is that you ask? Precisely Header Injection! When I was looking at urllib vulns earlier I dismissed it since it didn't seem useful, but surely good thing I read about it! Here are some [docs](https://github.com/python/cpython/issues/80457).

CRLF - Carriage Return (\r) Line Feed (\n) is a two-char sequence used in Windows and DOS to signal a newline. It's the Windows version of \n, and it applies to HTTP headers too!!

Cool! So we just need to inject a header now! 

First I tested with a webhook, and it *did* allow me to send a \r\n, but when I tried to inject a header it would break.

`url=https://webhook.site/705285b1-bcb1-4dd7-b433-8bf552d83669%0d%0a%0d%0a` worked but not when I specified a host.

But guess what - OUR fucking POST request had to have the company.tld header, not the crawler's GET. I figured this out many hours later, I can't comprehend why I hadn't tried this before looking at CRLF (which didn't work). 

So there's our flag!

![challenge-screenshot](flag.png#center)

---




