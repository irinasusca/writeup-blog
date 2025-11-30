+++
date = '2025-11-30'
draft = false
title = "Pico Here's A LIBC Writeup"
ShowToc = true
tags = ["picoCTF", "pwn", "buffer-overflow"]
+++

## Challenge overview


I am once again asking for you to pwn this **[binary](https://play.picoctf.org/practice/challenge/179)** 

![challenge-screenshot](pic1.png#center)

At first glance, the **vuln** looks like a 64-bit executable with a buffer overflow vulnerability. And since it's hinted in the title, most probably a ret2libc challenge. 

Upon checking, only `NX` is enabled. So this should make things fairly easy for us.

---

## Identifying the vulnerabilities

We can quickly check if there's a `/bin/sh` in memory, and there it is! Along with a `system` and also `execve`.

![challenge-screenshot](pic2.png#center)

Now, let's analyze the binary; there's some pretty weird variables in `.rodata`: 

![challenge-screenshot](pic3.png#center)

They're used inside our `do_stuff()` loop, to calculate how much input is going to be read. 

![challenge-screenshot](pic4.png#center)

`%[^\n]` is a *scan set*; What is a *scan set* you might ask?

Well, scan sets begin with `%[` and ends with `]`. The insides, in this case `^\n`, mean read everything except a newline. So basically, read everything until the first `\n` and store it in `s[112]`. So, classic buffer overflow.

And `%c` is probably just going to store that newline that we didn't read.

So, since we're working with 64-bit, let's find a `pop rdi; ret` gadget with `ropper`. We have one at `0x400913`.

The challenge includes a `libc.so.6` to download, and a Makefile that specifies the binary will try to use the `./libc.so.6` before the system-wide libc. After installing it, and trying to run the binary, I stumbled upon this error:

```python
./vuln
Inconsistency detected by ld.so: dl-call-libc-early-init.c: 37: _dl_call_libc_early_init: Assertion `sym != NULL' failed!
```
Which meant that my dynamic loader wasn't compatible with the challenge's `libc.so.6`. And they didn't give us a compatible dynamic loader to download.

After inspecting the `libc.so.6` with `strings`, and looking for `GLIBC` to see if we find any clues, we can find `GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.`.

Which is an older version of the system loader, the `ld-2.27.so` one, from `ubuntu:18.04`. I'm assuming this is a mistake in the challenge, but let's see if we can still solve this challenge.

## Finding the correct system loader

After some research, looks like we need to download both `ld-2.27.so` and `ld-linux-x86-64.so.2` and place them in the same folder as `vuln`.

I downloaded `glib27` **[here](https://mirrors.edge.kernel.org/ubuntu/pool/main/g/glibc/)** found as `libc6_2.27-3ubuntu1_amd64.deb glibc27` and did this, which got our chall working again: 

![challenge-screenshot](pic5.png#center)

Because we always need a specific command to run it using these libraries, we need to write this argument to `p.process()` in pwntools:

`p = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./vuln"])` 

Finally, it worked! And, unsurprisingly, we get different locations for our `/bin/sh` and `system` every time we run the challenge (`ASLR`). I found the offsets:

`binsh = libc + 0x1B40FA`

`system = libc + 0x14B37`

So first, we need to leak `libc`, the classic ret2plt way, `puts(elf.got['puts']`.

---

## The Exploit

Our `s[112]` input string starts at `ebp - 128`, so we start by adding `128*b'A'`padding in our payload, then another 8 bytes for `rbp`, (since we're on 64-bit; on 32-bit `rbp` is 4 bytes), then our `pop rdi; ret` gadget, `elf.got['puts']` as our function parameter, then the `elf.plt['puts']`, the action function we call, and then the address of `do_stuff` to return to it once the function is finished.

```python
p.sendline(b'A'*128 
         + b'\x90'*8
         + pop_rdi 
         + p64(elf.got['puts'])
         + p64(elf.plt['puts']) 
        + do_stuff)
```

![challenge-screenshot](pic6.png#center)

That looks like a `libc.so.6` address! In this instance, `puts` is located at `0x7f89b2212787`, and the address we print looks like `0x7f89b2280000`, and they are clearly different, but that's alright; We can just calculate the offset from `libc` to our leak with `gef` and problem solved.

We should use something like `libc_puts = u64(leaked.ljust(10, b"\x00"))`, but first get rid of the first two lines.

```python

p.recvlines(2)

leaked = p.recvline().strip().ljust(8, b"\x00")
leaked_puts = u64(leaked)
print(hex(leaked_puts))

```

This however would pad it to the wrong side, and the leak would look like `0x0000007f89b228` instead of `0x007f89b2280000`. So I replaced it with 

```python

p.recvlines(2)

leaked = p.recvline().strip().rjust(6, b"\x00").ljust(8, b"\x00")
leaked_puts = u64(leaked)
print(hex(leaked_puts))

```

To add two `x00`s to the left, and two to the right, and we finally get the proper format for the leak.


The offset from `libc` is `0x80000`, so we just subtract the offset from the leak, and we get `libc`!

![challenge-screenshot](pic7.png#center)

Now, we can calculate `system` and `/bin/sh` based on their offsets from `libc`, and add another payload that pops us a shell. The payload is essentially the same, but we change the function being called and its argument.

![challenge-screenshot](pic8.png#center)

What happened? Our `rdi` is correctly pointing to `/bin/sh`, but it looks like `system` isn't working as expected... After closer inspection, the offset we found was to a *string* "system". Oops. Let's try looking for the actual `libc` function.

The correct way to search for a *function*, not a string, in `gef` is `info functions system`.

![challenge-screenshot](pic9.png#center)

So the correct offset is at `0x4f4e0`. But we get another `EOF`. Most probably, this is an alignment issue, so we can just add another `ret;` gadget before calling `system`.

And we pop a shell!

![challenge-screenshot](pic10.png#center)

Now let's connect remotely:

![challenge-screenshot](pic11.png#center)

Well... This is getting annoying, especially after having to manually look for and download the files they didn't include and I doubt finding the missing linker was part of the challenge...

![challenge-screenshot](pic12.png#center)

I added a `string = p.recvlines(2), print(string)` to debug what's happening, and it looks like unlike locally, the garbage data is only getting printed on the first line. So we can just change it to `p.recvline()` and it should be fine.

![challenge-screenshot](pic13.png#center)

Are you kidding me?! Since when are we working with a canary? And the address getting leaked looks like a different one than the one we were working with... 

After checking again, it's because this time we get the full 8 bytes of the leak:

![challenge-screenshot](pic14.png#center)

So we need to figure out what is actually getting printed, to calculate the correct offset. Some outputs are:

`0x7f3ed7b84a30`

`0x7fe043473a30`

`0x7fc96755ba30`

`0x7f28f2774a30`

`0x7fd633bf9a30`

What seems to be the offset here? They all seem to share the `0xa30` ending but the 4th byte differs. 

I printed the `libc` symbols for our `libc.so.6`:

```python
puts offset: 0x80a30
system offset: 0x4f4e0
/bin/sh offset: 0x1b40fa
```

And would you look at that, it's quite exactly `puts`'s offset - so this time it works properly, unlike when we were testing locally. So we calculate our `libc` based on that, but we still bump into the `EOF` error.

```python
0x7efd239b1a30
0x7efd23931000
[*] Switching to interactive mode
timeout: the monitored command dumped core
[*] Got EOF while reading in interactive

```
Something's missing; Most probably a stack alignment issue. At this point I felt like I was missing something else, and I tried to find the solution online, but everything I did appeared to be in order.

So what *was* missing? I printed the received line before every line of code, and turns out we were getting the `timeout: the monitored command dumped core\n` *before* sending the `system` payload.

First guess - we didn't return into the right function, after the first payload. So let's change it from `do_stuff` to `main`. And - *finally* - we did it!

![challenge-screenshot](pic16.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/heresalibc.py)**.
