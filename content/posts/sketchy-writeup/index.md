+++
date = '2025-12-11'
draft = false
title = "Nullctf 2025 Sketchy Writeup"
ShowToc = true
tags = ["pwn", "buffer-overflow", "Ret2libc", "one-gadget"]
+++

## Challenge overview

This challenge was a part of the NullCTF 2025, made by tudor, with the description *sketchy stuff going on here i'm scared*.

Upon checking, we're dealing with `NX`, `PIE` and `ALSR` and no canary.

Let's take a look at the binary. We have two interesting functions, `main` and `handler`.

![challenge-screenshot](pic1.png#center)

Inside `main`, firstly, we are given the address of `main` (located at PIE address + `0x1265`), so we don't need to bother with leaking it. Then, a pointer `s` gets assigned the string *quite interesting stuff you're saying*.

Then, we  get to write 58 bytes into `buf`, which, `QWORD buf[6]`, stores 48 bytes. So we have a 10 byte buffer overflow.

Next, `buf` is searched for its first `\n` and modifies it into a null byte. Afterwards, it's checked whether the string inside `buf` is longer than 50 bytes, which calls a `sys_exit`.

Then, `puts(s)` is called, and we get to write a long hexadecimal address in `v6` via `scanf`. If the address is before `printf`'s address, we get to write 5 bytes in the address we chose for `v6` with `fgets`.

![challenge-screenshot](pic2.png#center)

What `handler` does is just start a 100 second timer when connection is established, and when the 100 seconds pass, call `puts("challenge timed out")` and `sys_exit`.

---

## The exploit

First of all, let's calculate the base of our PIE.

```python

p.recvuntil(b': ')
main = int(p.recv(14), 16)

```
So since the next move is probably leaking `libc`, it would be great to somehow make that `puts(s)` turn into a `puts(putsgot)`. Our best bet is the 10 byte buffer overflow we have at our disposal, our of which the `v8` eats 8, so that leaves us with 2 bytes. 

The string *quite interesting stuff you're saying* is located in the `.rodata`, as is the puts got. Since we get to overwrite only two of the LSB in `s`, that means the distance between the string and got isn't that far.

Basically, since `s` is a pointer to a `.rodata` address, we can modify it to point to another address in `.rodata` as long as they share everything except the last 2 bytes we can modify.

The only problem for now is the buffer overflow verification after that; but since it only checks for the first newline, and it turns it into a null byte aka string terminator, we can trick it into thinking our string ends early by adding a random newline inside our payload.

![challenge-screenshot](pic3.png#center)

Here, we can see by modifying the last byte to `0x20`, we end up printing another string in the `.rodata`. Now let's actually calculate the PIE offset to puts got and get that libc `puts_IO`!

```python

putsgot = PIE_base + elf.got['puts']
#we can modify the last two bytes -> since the dif to got is only two bytes we get got

payload = (b'\x00'*16+b'\n'+b'\x00'*39 + #padding to *p
		p64(putsgot)[:2] )

```

Great! Now we can parse it and calculate our actual libc base.

```python

leak = p.recvn(6)
puts_leak = u64(leak.ljust(8, b'\x00'))
print(hex(puts_leak))

#local
puts_offset = 0x585a0
system_offset = 0x2b110

#2.40
puts_offset=0x080be0
system_offset=0x51c30

#apparently it was 2.28
puts_offset=0x87be0


```

I struggled a little with finding the correct version of libc, I assumed it was 2.39 for a long time but apparently it was 2.28.

![challenge-screenshot](pic4.png#center)


---

The secret to actually solving this challenge was overwriting the right thing. Because of all the `sys_exit(0)` calls everywhere, and since after our `v6` overwrite no function was actually being called, we can think of two things: first, we can probably use our `handler` function, which calls `puts`, and second, overwrite the puts got in a way that we can pop a shell.

My first idea was overwriting puts got with `system`, but the problem was the argument of the function would be *challenge timed out*, not */bin/sh*. Same thing with `execve.` The solution here was using a `one_gadget`. We can look for one in our given `libc.so.6` like so:

![challenge-screenshot](pic5.png#center)

The one I went with was `0xef4ce`, since it seemed like the most promising. So since it's basically like a gadget except for libc, the actual address of it would be libc base + one_gadget. 

Alright, but after modifying the address with our gadget, the binary immediately calls `sys_exit` and we don't get that `puts` caused by the time out, so what can we do?

Well, since the program will wait until our full `fgets` input to actually call the `sys_exit` in main, we can do both at the same time.

By this I mean that if we only give some of the 5 bytes in `fgets`, let's say 3 is enough, and then we wait until the alarm starts, it will end our `fgets` early, make that overwrite with the 3 bytes we gave it (should be enough, since `puts` and our gadget share the same first 5 bytes), and call `puts` (now our shell).

```python

addr_putsgot = hex(putsgot)[2:].encode()
print(addr_putsgot)
p.sendline(addr_putsgot)

execve = 0xef4ce
#execve = 0xef52b
one_gadget = libc + execve
low3 = p64(one_gadget)[:3]


p.send(low3)

#now just wait for the alarm

```

After waiting 100 seconds, we pop a shell, and we get the flag!

![challenge-screenshot](win.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/nullctf2025/sketchy.py)**.
