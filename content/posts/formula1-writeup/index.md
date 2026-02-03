+++
date = '2026-02-02'
draft = false
title = 'CyberEdu formula1 Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

## Challenge overview

Only a champion can win this race. Enter the secret pit stop and claim your flag!

## Identifying the vulnerabilities

We're confronted with a login page, with two fields, `Only for F1 champions. Enter your first name and pit code to start your engine`. Entering a random username and random password would give an `Invalid username` error, but sending *max* (for Max Verstappen) would give an `Invalid pit code`. 

This is an Apache server, and it keeps setting our Cookie to `PHPSESSID=2a94c13c4f5edaae8191d18c9499278b` (on multiple instances).

I made a little python rockyou bruteforce, but we get an `Error! Automated activity detected!`. This made me believe we're going the right way about this.

Then I added these headers - 

```python
headers = {
    "Cookie": "PHPSESSID=e1274ed7687c47b09d28742923bc179a",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
}
```

And it worked. But it was going *excruciatingly* slow, I'm talking one request per second. And since the challenge is race themed, it might be a timing vulnerability. I tried all characters and digits, but there wasn't any character consistently sticking out time-wise.

I'd tried just about everything so I decided not to waste more time and looked for a writeup online and found [this](https://scant.ro/posts/rocsc-2025/). I was right about it being a race condition, but apparently what we needed was to send a bunch of requests in parallel.

I tried writing it in python with requests rather than burp, to practice, but I accidentally DoS-ed it.

It took me a while to realise, but turns out we also needed to send requests to `/flag.php` at the same time to create that race condition. So here is the python script that does just that:

```python

```

And here is proof it works:

![challenge-screenshot](flag.png#center)

That's it!

---

You can also find the script [here on my github]().




