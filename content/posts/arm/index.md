+++
date = '2026-05-10'
draft = false
title = 'arm'
ShowToc = true
tags = ["Materials"]
+++


## Why

Why not!

## References


[Read this in-depth tutorial](https://azeria-labs.com/writing-arm-assembly-part-1/)

[This](https://blog.perfect.blue/ROPing-on-Aarch64) explains it pretty quickly as well

And [here](https://www.ctfrecipes.com/pwn/architectures/aarch32/registers)

And this [book](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20A%20short%20guide%20on%20ARM%20exploitation.pdf)

## Installation

### aarch64

On my kali, all I managed to install was `sudo apt install qemu-user qemu-system-arm gdb-multiarch`.

To run the binary:

```bash
qemu-aarch64 ./prob
```

To debug, you must first `qemu-aarch64 -g 1234 ./prob`. Then, on another terminal:

```bash
gdb-multiarch -ex "target remote :1234"
```

It kept crashing for me, so I also had to add these options inside the debugger:

```bash
pwndbg> set follow-fork-mode parent
pwndbg> set detach-on-fork on
```

So the command looks more like 

```bash
gdb-multiarch -ex "target remote :1234" -ex "set follow-fork-mode parent" -ex "set detach-on-fork on" ./prob`.
```

### 32-bit arm

Same thing, but use `qemu-arm` instead.

## The important stuff

### aarch64

Now, to summarize:

- The registers are from `x0` to `x30`; the 32nd register is used as the stack pointer, kind of like `esp`, and called `[sp]`.

- The registers from `x0` to `x7` are used for function parameters

- The return address is stored in `x30`

- `x29` is the equivalent of `ebp`

I'll just include some screenshots from one of the links here:

![challenge-screenshot](arm1.png#center)

![challenge-screenshot](arm2.png#center)

So, quite a read.

And keep this layout in mind:

```bash
[A * offset]
[gadget addr]
<---- SP NOW HERE
```

Also interesting to note; Usually amd64 binaries with PIE load at something like `0x5555555?????` - but for aarch64, the standard PIE load base is `0xaaaaaaaa????`.

 0xfffffffffa50.0x2.0xfffff7f9df4c.0xfffffffffa04.0xfffffffffffffff0.0.0xaaaaaaaaac90.0xfffffffffd10.0xaaaaaaaaac54.0x1fb03ffe.

### 32-bit arm

todo....
