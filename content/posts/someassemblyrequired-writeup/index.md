+++
date = '2026-04-02'
draft = false
title = 'Pico Some Assembly Required 1, 2, 3, 4 Writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Some Assembly Required 1

Looking at `./G82XCw5CX3.js`, we can see some strange *wasm* file getting imported, `./JIFxzHyW8W`. I navigated to the directory and it immediately got downloaded.

*Note - just running strings on the file was fine too, I realised a little later, there wasn't necessarily any need to decompile the wasm.*

I decompiled it with Ghidra (more on that in [this post I made](irinasusca.github.io/writeup-blog/posts/wasm/)).  

We can see in the `check_flag` function it's getting checked against the memory at `0x400`, which just so happens to be the flag.

![challenge-screenshot](flag1.png#center)

I ran this Ghidra Jython script to print the memory starting at `0x400` and we can copy the flag:

![challenge-screenshot](script.png#center)

## Some Assembly Required 2

For this one, I tried to deobfuscate the code myself, and it looked a little like this:

```js

let exports
;(async () => {
  let wasmFile = await fetch("./aD8SvhyVkb"),
    wasm = await WebAssembly.instantiate(await wasmFile.arrayBuffer()),
    wasmResult = wasm["instance"]
  exports = wasmResult[exports]
})()

function onButtonPress() {
  let input = document[getElemendById](input)[value]
  for (let i = 0; i < input.length; i++) {
    exports[copy_char](input[charCodeAt](i), i)
  }
  exports.copy_char(0, input[length])
  exports[check_flag]() == 1
    ? (document.getElementById(result)[innerHTML] = "Correct!")
    : (document[getElementById](result).innerHTML = "Incorrect!")
}
```

This time, the string in `check_flag` was `xakgK\Nsn08m?80jj:i;j:m0?klnm<i1:8>iljinu`. Taking a look at `copy_char`, it looks like it was xor-ing each character with 8.

![challenge-screenshot](copychat.png#center)

We just xor that with 8 again through cyberchef and we get the flag, `picoCTF{f80e708bb2a3b2e87cdfe4a9206adbaf}`.
 
## Some Assembly Required 3
 
I was trying to tick off everything in the medium web category, and I thought to look in the hard one to see if there are any more continuations to this, and guess what! Now let's take a look and see how hard these *really* are.

I used [this deobfuscator](https://deobfuscate.relative.im/) again and replaced the obfuscated hex name variables with what they really were, this time by running the js code and just printing it instead of calculating it myself:

![challenge-screenshot](viuh.png#center)

```js
function onButtonPress() {
  let doc = document[getElemendById](input)[value]
  for (let i = 0; i < doc[length]; i++) {
    exports[copy_char](doc.charCodeAt(i), i)
  }
  exports[copy_char](0, doc[length)
  exports[check_flag]() == 1
    ? (document[getElemendById](result)[innerHTML] =
       "Correct!")
    : (document[getElemendById](result).innerHTML = "Incorrect!")
}
```

So, pretty much the exact same thing, with an operation being done on each character. This is what it looked like:

![challenge-screenshot](copychar2.png#center)

So for each character in `input[i]` we xor it with what's at address `0x42f - i % 5`. That leaves whats in between `0x42B` and `0x42F`. 

I wrote this little script, and using it we get the flag `picoCTF{3a09d0a084e8032bf66c5171c4049aff}`.

```python
r1 = 0xf1
r2 = 0xa7
r3 = 0xf0
r4 = 0x07
r5 = 0xed
r = [r1, r2, r3, r4, r5]

bytes = b"\x9dn\x93\xc8\xb2\xb9A\x8b\x94\x90\xdd>\x94\x97\x90\xdd?\xc4\xc2\xc9\xdd4\xc2\xc5\x97\xdb1\x93\x92\xc0\xda6\x93\x93\xc1\xd9>\x91\xc1\x97\x90"

print(bytes)

i = 0
while(i<len(bytes)):
    j = 4 - i%5
    print(chr(bytes[i]^(r[j])), end="")
    i=i+1
```

## Some Assembly Required 4

Finally the last one! I looked at the js file and I'm assuming everything is the same as the previous challenge. This time, `check_flag` got a little more complicated, and it was the one responsible for the char-by-char xor-ing.

![challenge-screenshot](checkflag.png#center)

This time an action is being done after the xor, which is the swap. So we need to do the swap first in our decode script. 

```python
bytes2 = bytearray(b'\x18j|a\x118i7\x1fYyY>\x1cVc\rB\x1d~l9\x1cZ!]c\x11\x00b\x05IK~a4\x1cW(\x0fR')

#we need to do this in reverse, so the swap first

j = 0
while(j<len(bytes2)):
    if(j%2==0 and j+1<len(bytes2)):
        bytes2[j], bytes2[j+1] = bytes2[j+1], bytes2[j]
    j=j+1


#now the XOR in reverse

i = len(bytes2)-1

while(i>=0):
    bytes2[i] = bytes2[i] ^ 0x14
    if(0<i):
        bytes2[i] = bytes2[i] ^ bytes2[i-1]
    if(2<i):
        bytes2[i] = bytes2[i] ^ bytes2[i-3]
    bytes2[i] = bytes2[i] ^ (i%10)
    if(i%2==0):
        bytes2[i] = bytes2[i] ^ 9
    else:
        bytes2[i] = bytes2[i] ^ 8
    if(i%3==0):
        bytes2[i] = bytes2[i] ^ 7
    elif(i%3==1):
        bytes2[i] = bytes2[i] ^ 6
    else:
        bytes2[i] = bytes2[i] ^ 5
    i=i-1
        
print(bytes2.decode('latin-1'))
```

Running this gives us the flag, `picoCTF{1c4abb877272112e39233c05ade7abbb}`.
