+++
date = '2026-01-04'
draft = false
title = 'CyberEdu threadz Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "threads", "shellcode"]
+++


## Challenge overview

Threads are so cool! And secure! So secure that I store all my **[secrets](https://app.cyber-edu.co/challenges/8f45b420-44a3-11ed-8fdf-1ba87180e9f3?tenant=cyberedu)** there

Note 1: The flag is broken into chunks of 4 characters, like this: volatile __thread unsigned int flag1 = '{CFT';

The letters in the chunks are reversed for your convenience, and the chunks are defined in order

Note 2: The binary is intentionally not given.

Note 3: The program will read 0x1000 bytes of shellcode, stored into a mmap-ed region with RWX permissions

---

Alright, interesting! So we're blind here. We get 4096 bytes of shellcode to try and figure out the flag.

---

## Identifying the vulnerabilities

My first attempt was to invoke a shell, but I already suspected it wouldn't work, because of the interesting flag format. 

```python
shell = asm(shellcraft.sh())

p.recvuntil(b"!!!\n")
p.sendline(shell)
```

Our challenge gives us a big hint - that the flag is stored per-thread, not on the stack or heap. So in the TLS (thread local storage). In x86_64 linux that's the fs: base.

I didn't know anything about threads so I solved this challenge with great help from a friend (ChatGPT). 

What __thread really means is if, for example, we run `__thread unsigned int flag1 = '{CFT';`, is every thread would get its own copy of flag1.

The CPU has some segment registers, `fs` and `gs`. To access thread-local bookkeeping, linux uses `fs` (and Windows uses `gs` but who cares about Windows, right?).

So `fs:0x0` is memory relative to this thread’s TLS base. There's multiple threads though, each with its own TLS base. And at that base is where the TCB (thread control base) lives, which is just kernel and libc data about the thread. But that's not thread variables. Which is what we need if you recall.

Inside this *TCB*, especially at `fs:0x8` on amd64 glibc, is a pointer to the **DTV** (a pointer array, loaded once per module, with TLS data). 

![challenge-screenshot](explain.png#center)

(Except the "flag lives here" is wrong, because it was at DTV + 0x16, so that's esentially the third thing, probably the binary, don't know enough about threads to say for sure)

Then, we cooked this shellcode:

```python
context.os = "linux"

sc = asm(r"""
    /* rbx = dtv */
    mov rbx, qword ptr fs:[0x8]

    /* rsi = dtv[0] (first TLS module) */
    mov rsi, [rbx + 16]

    mov rdi, 1          /* stdout */
    mov rdx, 256        /* dump size */

    mov rax, 1          /* write */
    syscall

    xor rdi, rdi
    mov rax, 60
    syscall
""")
```

Which does exactly that, prints the third thing pointed to by the DTV. And that was the flag variable!

![challenge-screenshot](flag.png#center)





---

## The exploit




---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/threadz.py)**.
