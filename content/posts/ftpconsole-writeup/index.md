+++
date = '2025-12-03'
draft = false
title = "CyberEdu ftp-console Writeup"
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Ret2libc"]
+++

## Challenge overview


We got a very strange **[ftp console?](https://app.cyber-edu.co/challenges/9d17bf1a-69a7-418a-b3bb-569286ab8d7b?tenant=cyberedu)** Can you retrive the flag?

![challenge-screenshot](pic1.png#center)

At first glance, the **ftp_server** looks like a 32-bit executable, and as hinted by the name, a FTP (File Transfer Protocol) server mockup.

Upon checking, every protection is disabled, so that's nice! Now let's take a look at the binary. 

![challenge-screenshot](pic1.png#center)

We have a `main` function that calls `login`, and we can already see some interesting things going on.

---

## Identifying the vulnerabilities

First of all, the program leaks the location of `system`, so that's great! From there on, we can easily calculate `/bin/sh`, at `system + 0x174c32`, through `gef`.

```python

p.recvuntil('\n')
p.sendline(b'kkt')
p.recvuntil(b': ')

system = int(p.recv(10), 16)
log.success(f'system: {hex(system)}')

binsh = system + 0x174c32
log.success(f'binsh: {hex(binsh)}')

```


---

## The Exploit

Now, to use this buffer overflow; We read 100 bytes in `s1[32]`, which is at `ebp - 76`. For some reason the `printf("PASS ")` and `printf("USER ")` don't appear locally for me, so I might have to modify them later, for the remote version.

![challenge-screenshot](pic3.png#center)

And so we pop a shell locally! Now let's try remotely as well.

---

![challenge-screenshot](pic4.png#center)

That's, well, interesting. The `./flag.sh` makes me think we did something right. I modified the `p.recvuntil()` to consider the `printf("PASS ")` and `printf("USER ")` as getting displayed, but we get a similar error. Maybe the error is the offset from `system` to `/bin/sh`. 

So, using [blukat](https://libc.blukat.me/?q=system%3A0xf7d79170&l=libc6_2.35-0ubuntu3.11_i386) with the known `system` value, I identified the remote version as `2.35`, and guess what - shell! 

![challenge-screenshot](pic5.png#center)

After a `ls`, the only two files we see are `flag.sh` and `ftp_server`. After digging around files for the flag, I decided to just search the entire system for it using some commands. In the end, this is what worked:

![challenge-screenshot](pic6.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/ftpconsole.py)**.
