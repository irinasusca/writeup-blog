+++
date = '2026-02-04'
draft = false
title = 'CyberEdu asmadventure Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "rev"]
+++


## Challenge overview

Because it's a reverse engineering chall I'm including the **[link](https://app.cyber-edu.co/challenges/9e65d240-9d72-4a37-bd46-ecaf20fd6630?tenant=cyberedu)**. 

---

Ieri seară am primit o alertă privind un shellcode executat de un binar suspicios.

Poți analiza ce se întâmplă și să descoperi parola infractorului?

---

We receive a main binary. Very strangely, looking at this in IDA, it doesn't look like anything. 

![challenge-screenshot](pic1.png#center)

This is literally it. All of it.

It allocates a rwx memory region of 559 bytes with 0.

It xors each byte of `unk_4020` with 'A', moves it into v5, then makes the last 8 bytes of v5 become `unk_4247`.

It does a bunch of weird stuff in that `qmemcpy` we'll get to in a moment, and then calls the function v5 points to. And that's *all* of the code.

## Identifying the vulnerabilities

Let's look at the `qmemcpy`. We know that it should look like `memcpy(&dest, &addr, numBytesToCopy)`.

 - **The dest**: `(void *)(((unsigned __int64)v5 + 8) & 0xFFFFFFFFFFFFFFF8LL)`; it takes `(v5+8)` and zeros the last three bits. Essentially this aligns this for a 64-bit system, making it divisible by 8. Basically `value - value % 8` is what's happening. Then it casts that to a pointer. Equivalent to `v5+8 - v5%8`.
 

- **The data**: `(const void *)(&unk_4020 - (_UNKNOWN *)((char *)v5 - (((unsigned __int64)v5 + 8) & 0xFFFFFFFFFFFFFFF8LL)))`; We're back at working with our `unk_4020`, and we're extracting `v5 - addr`. So that would be `unk_4020 - (v5%8 - 8)`.

- **The length**: - `8LL * ((((_DWORD)v5 - (((_DWORD)v5 + 8) & 0xFFFFFFF8) + 559) & 0xFFFFFFF8) >> 3));`: First, the `>>3` (divide by 8) and multiplicate by 8 just cancel each other out, so let's omit bothering with it. The middle part - `v5 - (v5+8 - (v5+8)%8) +559` = `v5 - v5 - 8 + v5%8 +559` = `(551 + v5 % 8)`. Then we &-8 that as well. The &-8 always gives something <= number, the biggest number divisible by 8, smaller than our number. And if the v5%8 is bigger than 0, that number becomes 552. Otherwise, it's 544.

Let's rewrite this memcpy:

```c
memcpy(
    v5 + 8 - v5%8,
    pie + 4020 + (8 - v5%8)
    552
    );
```

That was annoying! (And note from the future, absolutely unnecessary! I still left this in, greatly reduced maths, so you can see how long this took).

Now let's examine the binary behaviour with `gef`. I put a breakpoint on main and just followed it, and at the end, it called the v5 I assume, leading us to `0x7ffff7fb7000`. There, I saw our first syscall - `0x9`. Looking that up in a syscall table, that's mmap.

![challenge-screenshot](pic2.png#center)

Then, it syscall-ed again, this time with rax 0, so that's *read*. But what does it read from? From what file descriptor? It's in one of the parameter registers, more exactly `rdi`. Which is 0, aka stdin. And `rdx` is the count, in this case `0x100`, so I pasted `0x100*'a'` and it continued assemblying. 

![challenge-screenshot](pic3.png#center)

![challenge-screenshot](read.png#center)

So now we can respond to this question about the syscall:

![challenge-screenshot](grila.png#center)

I kept looking through the assembly, and at some point `rax` became a pointer to a string "unix:path=/run/user/1000/bus". This *is* supposed to be malware, I think. Good thing I've been running it for an hour now! Luckily I haven't got any money.

Problem is, I've no clue how I managed to stumble upon it. I was just going step-into-to-step-into, and setting all the registers getting checked in je's to zeros, to continue the process. 

I changed a bunch of random values *again* to satisfy some random conditions, whenever I felt like it. Genuinely. Then, when I saw it was trying to *kill* me, I changed the syscall rax from 60 to 39 (a syscall that does nothing), so I can stay, and...

![challenge-screenshot](what.png#center)

Printing the stack in this state:

```bash
0x7fffffffe0fe: "COMMAND_NOT_FOUND_INSTALL_PROMPT=1"
0x7fffffffe121: "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"
0x7fffffffe157: "DESKTOP_SESSION=lightdm-xsession"
0x7fffffffe178: "DISPLAY=:0.0"
0x7fffffffe185: "DOTNET_CLI_TELEMETRY_OPTOUT=1"
0x7fffffffe1a3: "GDMSESSION=lightdm-xsession"
0x7fffffffe1bf: "HOME=/home/kali"
0x7fffffffe1cf: "LANG=en_US.UTF-8"
0x7fffffffe1e0: "LANGUAGE="
0x7fffffffe1ea: "LOGNAME=kali"
0x7fffffffe1f7: "NMAP_PRIVILEGED="
0x7fffffffe208: "PANEL_GDK_CORE_DEVICE_EVENTS=0"
0x7fffffffe227: "PATH=/home/kali/.local/share/gem/ruby/3.3.0/bin:/home/kali/.pyenv/plugins/pyenv-virtualenv/shims:/home/kali/.pyenv/shims:/home/kali/.pyenv/bin:/home/kali/.local/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/home/kali/.dotnet/tools"
0x7fffffffe33e: "POWERSHELL_TELEMETRY_OPTOUT=1"
0x7fffffffe35c: "POWERSHELL_UPDATECHECK=Off"
0x7fffffffe377: "PWD=/home/kali/Downloads"
0x7fffffffe390: "QT_ACCESSIBILITY=1"
0x7fffffffe3a3: "QT_AUTO_SCREEN_SCALE_FACTOR=0"
0x7fffffffe3c1: "QT_QPA_PLATFORMTHEME=qt5ct"
0x7fffffffe3dc: "SESSION_MANAGER=local/kali:@/tmp/.ICE-unix/896,unix/kali:/tmp/.ICE-unix/896"
0x7fffffffe428: "SHELL=/usr/bin/zsh"
0x7fffffffe43b: "SHLVL=1"
0x7fffffffe443: "SSH_AGENT_PID=1003"
0x7fffffffe456: "SSH_AUTH_SOCK=/home/kali/.ssh/agent/s.RDJpj98jBr.agent.53nQ35rQUj"
0x7fffffffe498: "TERM=xterm-256color"
0x7fffffffe4ac: "USER=kali"
0x7fffffffe4b6: "WINDOWID=0"
0x7fffffffe4c1: "XAUTHORITY=/home/kali/.Xauthority"
0x7fffffffe4e3: "XDG_CACHE_HOME=/home/kali/.cache"
0x7fffffffe504: "XDG_CONFIG_DIRS=/etc/xdg"
0x7fffffffe51d: "XDG_CONFIG_HOME=/home/kali/.config"
0x7fffffffe540: "XDG_CURRENT_DESKTOP=XFCE"
0x7fffffffe559: "XDG_DATA_DIRS=/usr/share/xfce4:/usr/local/share/:/usr/share/:/usr/share"
0x7fffffffe5a1: "XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/kali"
0x7fffffffe5d1: "XDG_MENU_PREFIX=xfce-"
0x7fffffffe5e7: "XDG_RUNTIME_DIR=/run/user/1000"
0x7fffffffe606: "XDG_SEAT=seat0"
0x7fffffffe615: "XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat0"
0x7fffffffe649: "XDG_SESSION_CLASS=user"
0x7fffffffe660: "XDG_SESSION_DESKTOP=lightdm-xsession"
0x7fffffffe685: "XDG_SESSION_ID=2"
0x7fffffffe696: "XDG_SESSION_PATH=/org/freedesktop/DisplayManager/Session0"
0x7fffffffe6d0: "XDG_SESSION_TYPE=x11"
0x7fffffffe6e5: "XDG_VTNR=7"
0x7fffffffe6f0: "OLDPWD=/home/kali/Downloads"
0x7fffffffe70c: "PYENV_ROOT=/home/kali/.pyenv"

```

But this isn't extremely useful. I started using my brain a little bit, and my conclusion was that the following:

The memory at `unk_4020` becomes actual assembly instructions *after* that xor with 'A'; That's the weird shellcode being executed. So if we break after that xor, we can view the actual shellcode.

And here it is:

```asm
xor    rdi,rdi
push   0x100
pop    rsi
mov    rdx,0x3
mov    r10,0x22
mov    r8,0xffffffffffffffff
xor    r9,r9
mov    rax,0x9
syscall
mov    rsi,rax
sub    rax,rax
push   0x100
pop    rdx
syscall
mov    rbp,rsi
mov    r15,rsi
mov    rax,0x50
add    rbp,rax
add    r15,0x4
mov    rdx,0x22
mov    r12,rbp
and    r12,0xff
xor    rdx,r12
xor    dl,BYTE PTR [r15]
test   dl,dl
je     0x555555558089
jmp    0x55555555808c
inc    BYTE PTR [rbp+0x0]
inc    rbp
inc    r15
xor    rax,rax
mov    bl,0x30
mov    al,bl
sub    al,0x33
test   al,al
je     0x5555555580a3
inc    bl
jmp    0x555555558097
sub    bl,BYTE PTR [r15]
test   bl,bl
je     0x5555555580ac
jmp    0x5555555580af
inc    BYTE PTR [rbp+0x0]
inc    rbp
inc    r15
push   0x10000
pop    rax
shr    eax,1
and    eax,0xffff
xor    eax,0xdf76
mov    bx,WORD PTR [r15]
xor    rax,rbx
or     rax,rax
je     0x5555555580d5
jmp    0x5555555580db
inc    BYTE PTR [rbp+0x0]
inc    BYTE PTR [rbp+0x1]
add    rbp,0x2
add    r15,0x2
movabs rax,0xffb2a25b948b4475
xor    rbx,rbx
mov    rcx,0x8
mov    rdx,rax
mov    rsi,0x0
mov    r8,rdx
and    r8,0xff
mov    r9,rsi
add    r9,0x1
shl    r9,0x3
sub    r8,r9
mov    r10,rbx
shl    r10,0x8
or     r10,r8
mov    rbx,r10
shr    rdx,0x8
inc    rsi
loop   0x555555558101
bswap  rbx
mov    rax,QWORD PTR [r15]
shl    rax,0x8
shl    rbx,0x8
sub    rax,rbx
cmp    rax,0x0
je     0x555555558148
jmp    0x555555558163
mov    rcx,0x7
mov    r10,0x0
inc    BYTE PTR [rbp+r10*1+0x0]
inc    r10
dec    rcx
jne    0x555555558156
add    r15,0x7
add    rbp,0x7
cmp    BYTE PTR [r15],0x7d
je     0x555555558173
jmp    0x555555558176
inc    BYTE PTR [rbp+0x0]
sub    rbp,0xf
sub    r15,0xf
push   0x1000
pop    rax
shl    rax,0x10
imul   rax,rax,0x4
add    rax,0xf000000
push   0x530000
pop    rcx
push   0x1000
pop    rdi
imul   rdi,rdi,0x4
add    rdi,0x300
mov    rsi,0xff
sub    rsi,0x84
add    rax,rdi
add    rax,rsi
add    rax,rcx
xor    rbx,rbx
mov    ebx,DWORD PTR [r15]
bswap  eax
cmp    eax,ebx
je     0x5555555581ce
jmp    0x5555555581e9
mov    rcx,0x4
mov    r10,0x0
inc    BYTE PTR [rbp+r10*1+0x0]
inc    r10
dec    rcx
jne    0x5555555581dc
mov    rcx,0x10
mov    rdx,rbp
cmp    BYTE PTR [rdx],0x1
jne    0x555555558202
inc    rdx
dec    rcx
jne    0x5555555581f3
jmp    0x55555555820c
xor    rdi,rdi
mov    eax,0x3c
syscall
movabs rax,0xa21216972
push   rax
movabs rax,0x61746963696c6566
push   rax
mov    rdi,0x1
lea    rsi,[rsp]
mov    rdx,0xd
mov    rax,0x1
syscall
mov    rdi,0x3c
xor    rsi,rsi
mov    eax,0x3c
syscall 
```

What this does is validate a password in chunks. *That's* what those checks were. I asked Gemini to translate this to a better C, and it thought it was some sort of game: 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <byteswap.h>

int main() {
    // 1. Allocate 256 bytes of RW memory (rax = 0x9: mmap)
    uint8_t *mem = mmap(NULL, 0x100, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return 1;

    // 2. Read input from stdin (rax = 0x0: read)
    read(0, mem, 0x100);

    // Scoreboard starts at mem + 0x50. 
    // If a check passes, we increment values here.
    uint8_t *scoreboard = mem + 0x50;
    uint8_t *input_ptr = mem + 0x4; // Start checking from 5th character
    int score_idx = 0;

    // --- CHECK 1: Single Byte Logic ---
    // (0x22 ^ (uintptr_t)scoreboard & 0xFF) == input[4]
    uint8_t check1 = 0x22 ^ ((uintptr_t)scoreboard & 0xFF);
    if (input_ptr[0] == check1) {
        scoreboard[score_idx++]++;
        input_ptr++;
    }

    // --- CHECK 2: Finding '3' via loop ---
    // The assembly loop effectively searches for 0x33 ('3')
    uint8_t target = 0x33; 
    if (input_ptr[0] == target) {
        scoreboard[score_idx++]++;
        input_ptr++;
    }

    // --- CHECK 3: Word/Short check ---
    // (0x10000 >> 1) ^ 0xDF76 = 0x8000 ^ 0xDF76 = 0x5F76
    uint16_t word_check = 0x5F76;
    if (*(uint16_t *)input_ptr == word_check) {
        scoreboard[score_idx++] = 1;
        scoreboard[score_idx++] = 1;
        input_ptr += 2;
    }

    // --- CHECK 4: 64-bit obfuscated loop ---
    // This reconstructs a 64-bit value from 0xFFB2A25B948B4475
    // and compares 7 bytes of it against the input.
    uint64_t magic = 0xFFB2A25B948B4475;
    uint64_t rbx = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t byte = (magic & 0xFF) - ((i + 1) << 3);
        rbx = (rbx << 8) | byte;
        magic >>= 8;
    }
    rbx = __builtin_bswap64(rbx);

    // Compare 7 bytes
    if (((*(uint64_t *)input_ptr) << 8) == (rbx << 8)) {
        for (int i = 0; i < 7; i++) scoreboard[score_idx++] = 1;
        input_ptr += 7;
    }

    // --- CHECK 5: Single character '}' ---
    if (input_ptr[0] == 0x7D) {
        scoreboard[score_idx++] = 1;
    }

    // --- CHECK 6: Large Constant Math ---
    // The code does complex math to result in a 32-bit constant
    uint32_t val = ((0x1000 << 16) * 4 + 0xF000000) + (0x1000 * 4 + 0x300) + (0xFF - 0x84) + 0x530000;
    val = __builtin_bswap32(val);

    input_ptr -= 15; // Moves pointer back to check a different segment
    if (*(uint32_t *)input_ptr == val) {
        for (int i = 0; i < 4; i++) scoreboard[score_idx++] = 1;
    }

    // --- FINAL VALIDATION ---
    // Verify that the first 16 bytes of the scoreboard are all 0x1
    for (int i = 0; i < 16; i++) {
        if (mem[0x50 + i] != 1) {
            _exit(0); // Fail silently
        }
    }

    // If passed: Print "felicitations!"
    const char *msg = "felicitations!";
    write(1, msg, 13);

    _exit(60); // Exit
    return 0;
}
```

I thought since Gemini understood this assembly so good, it might give us a clue, but instead it did all the maths for us and gave us the flag. Whoops. It did do a lot of maths.

![challenge-screenshot](flag.png#center)

The human way to do it, was go through the lines of assembly, and guess when the flag chunks would be loaded in registers for checking and take them from there. In this screenshot, for example, `rbx` was equal to a part of the flag, and `rax` was holding our input, and they were being compared. A bit tedious but, that would be the non-AI way to do it.

![challenge-screenshot](idea.png#center)

---

Anyways, thanks for reading!
