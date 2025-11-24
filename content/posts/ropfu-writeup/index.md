+++
date = '2025-11-24T21:09:36+02:00'
draft = false
title = 'Pico Ropfu Writeup'
ShowToc = true
tags = ["picoCTF", "pwn", "buffer-overflow", "rop"]
+++

## Challenge overview


What's ROP? Can you exploit the following **[program](https://play.picoctf.org/practice/challenge/292)** to get the flag?

![challenge-screenshot](pic1.png#center)

At first glance, the **vuln** looks like a 32-bit executable with a buffer overflow vulnerability.

---

## Identifying the vulnerabilities

Analyzing the binary, it doesn't look like anything special, just an ordinary buffer overflow.

We don't seem to have a `/bin/sh` in memory so this probably means we have to execute a ret2reg.


![challenge-screenshot](pic3.png#center)

That means we need to make our own `bin/sh` and point to it, and since the `vuln` *returns* the `gets`, that means `eax` will hold the `gets` return value. And the return value of `gets` is a pointer to the input value!

This is because `eax/rax` usually holds the current function's return value.


![challenge-screenshot](pic4.png#center)

Would you look at that, no NX! So we can execute the code right on the stack! Since we have a large enough overflow (28 bytes), we don't need to worry getting a shell.

That means we can just get a `jmp eax` gadget, and write our `shellcraft.sh()` at the start the input buffer.

---

## The Exploit

![challenge-screenshot](pic5.png#center)

Well, looks like we need to write the shellcode ourselves, `shellcraft.sh()` was too large after all...

I tried a bunch of shellcode that kept getting me segmentation faults, that I won't include, and I tried fitting it all in our buffer before the `jmp eax` gadget, and I managed to get all the registers required right (for `execve`, `ebx` needs to be a pointer to `/bin/sh`, and `ecx` and `edx` need to be 0)

After I set the address after `eip`, `eip+4`, to be a null-terminated `/bin/sh`, I noticed `esp` would become that value.

So, I tried  doing
```python
    mov ebx, esp      
    xor ecx, ecx
    xor edx, edx
    mov al, 0x0b
    int 0x80
```
    
And my mistake was most likely that I messed with the stack frame, since `execve` kept returning error `0xffffff74 = -140 = ERFAULT`.

But then I thought, if after the `jmp eax` the value at `eip+4` goes into `esp`, why don't we *write the shellcode* in  `eip+4`, then just `jmp esp` to said shellcode?

![challenge-screenshot](pic7.png#center)

That way, we can just use `shellcraft.sh()`, since we have unlimited space.

Since `jmp esp` is just 2 bytes, we pad with 26 more nops to its left.

```python
payload =  b'\x90'*26
payload += asm('jmp esp')
payload += jmp_eax
#this will become esp after we execute jmp eax.
newshell = asm(shellcraft.sh())
payload += newshell
```

---

![challenge-screenshot](pic9.png#center)

And it works!

The rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/ropfu.py)**.
