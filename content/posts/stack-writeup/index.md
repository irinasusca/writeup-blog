+++
date = '2025-12-03'
draft = false
title = 'CyberEdu Stack Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn"]
+++

## Challenge overview

You can't run shellcode if all registers are 0, **[right](https://app.cyber-edu.co/challenges/cd88b0e0-44a2-11ed-8a0d-17ff1fb32f1f?tenant=cyberedu)**?

![challenge-screenshot](pic1.png#center)

Our binary **main** is a 64-bit executable with an obvious buffer overflow vulnerability. Let's take a look at it using a disassembler. 

![challenge-screenshot](pic2.png#center)

We only have one function, `main`, which `mmap`s `dest`, copies 3 bytes of what's inside `&unk_2027` into `dest`, then lets us write 0x1000 bytes into `dest+3`. That means our buffer overflow is only 3 bytes, though.  Afterwards, it executes this assembly shellcode:

```python
__asm
  {
    vpxord  zmm0, zmm0, zmm0
    vmovdqa64 zmm1, zmm0
    vmovdqa64 zmm2, zmm0
    vmovdqa64 zmm3, zmm0
    vmovdqa64 zmm4, zmm0
    vmovdqa64 zmm5, zmm0
    vmovdqa64 zmm6, zmm0
    vmovdqa64 zmm7, zmm0
    vmovdqa64 zmm8, zmm0
    vmovdqa64 zmm9, zmm0
    vmovdqa64 zmm10, zmm0
    vmovdqa64 zmm11, zmm0
    vmovdqa64 zmm12, zmm0
    vmovdqa64 zmm13, zmm0
    vmovdqa64 zmm14, zmm0
    vmovdqa64 zmm15, zmm0
    vmovdqa64 zmm16, zmm0
    vmovdqa64 zmm17, zmm0
    vmovdqa64 zmm18, zmm0
    vmovdqa64 zmm19, zmm0
    vmovdqa64 zmm20, zmm0
    vmovdqa64 zmm21, zmm0
    vmovdqa64 zmm22, zmm0
    vmovdqa64 zmm23, zmm0
    vmovdqa64 zmm24, zmm0
    vmovdqa64 zmm25, zmm0
    vmovdqa64 zmm26, zmm0
    vmovdqa64 zmm27, zmm0
    vmovdqa64 zmm28, zmm0
    vmovdqa64 zmm29, zmm0
    vmovdqa64 zmm30, zmm0
    vmovdqa64 zmm31, zmm0
    jmp     rax
  }
```

What this chunk of shellcode does is, as the challenge description suggests, *clears all the zmm registers*. So, basically, turn everything to 0.

---

## Identifying the vulnerabilities

We don't need to worry about a canary, but the binary does have `NX` and `PIE` enabled.

The value at `&unk_2027` is `0xc03148`, after inspecting with `gdb`.

Okay, so what seems interesting is the `jmp rax` at the end of the asm instructions. Most likely, the return of `read` will be stored in `rax`, after the `read`. So let's set a breakpoint inside `main`, before the asm code, to see what `rax` looks like.

![challenge-screenshot](pic3.png#center)

Interesting! This looks like `dest`, the 3 bytes inside `&unk_2027`, and the rest of our string! So `jmp rax` will jump to `dest`, to our input - problem is, it has to look like
`0xa.....c03148`. So what can we do with this? It's already pretty bad, the `a` really ruins it (the newline).

![challenge-screenshot](pic4.png#center)

What's more, the program terminates with `SIGILL` before we even reach the `jmp rax`. This might be an us-problem though.

I found that we can get rid of the `a` in our payload by completely `ljusting` the `dest` (4096 bytes) with null bytes, which causes the `a` to be appended *in* those 3 bytes that aren't a part of `dest`. So that solves the newline problem.


![challenge-screenshot](pic5.png#center)

As expected, their program doesn't crash, and probably executes the `jmp rax`. That's settled, so let's go back to debugging.

Something important - `dest` is stored in `rwx` data - this means we can execute code inside `dest`. And since my program crashes really early on, it's possible that the `rax` we see to not be accurate, so that it might not point to `dest` in the actual remote binary. 

![challenge-screenshot](pic6.png#center)

Alright, so that means that these bytes - `0xc03148` - are actually being interpreted as shellcode! And `0xc03148` - `48 31 c0` - as opcode is `xor rax, rax`! Looks right! So we just need to add a payload here. Unfortunately, we can't really test locally, so we can't debug properly.

![challenge-screenshot](pic7.png#center)

My idea was a payload like this:

```python 
shellcode = b'\x90'*8+ asm(shellcraft.sh())
payload = shellcode.ljust(4096, b'\x90')
print(payload)
```

But remotely, we keep getting `EOF`. After a bit of research, turns out the challenge is broken, and the solution was something along these lines.
