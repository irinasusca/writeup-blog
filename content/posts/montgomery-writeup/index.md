+++
date = '2026-02-04'
draft = false
title = 'CyberEdu montgomery Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "Format-String"]
+++


## Challenge overview

E prima data cand ai un contact cu o proba de pwn? Acest exercitiu s-ar putea sa fie pentru tine.

PS: Acest serviciu merge cu netcat.

---

## Identifying the vulnerabilities

This is just a basic format string vulnerability. Leaking from `$69%p` to `$100%p`, we get the flag but in that fuckass format that I would usually put in a string reverser, 8 ASCII by 8 ASCII. But not this time. I wrote a script.

![challenge-screenshot](kkt.png#center)

*So annoying*.

---

## The exploit


Anyways, here's the hex detangler script I made:

```python
#split into 8 byte chunks and hex decode.
string = input("Enter tangled string:")
num = input("Enter chunks size (4 or 8 probably):")
num = int(num, 10)

i=0

while(i <= len(string)):
   chunk=string[i:i+num][::-1]
   #chunk = int(chunk, 16)
   print(chunk, end='')
   i=i+num
```

I will also be adding this to my github **[here](https://github.com/irinasusca/ctf-writeups/blob/main/misc/hexdetangle.py)**.

The flag is `CTF{230952df575051546fa84c60e8ef2a9c7e5576dc08eab3ea20c55d719351c90a}` and the answer to the quiz question is `printf`.


