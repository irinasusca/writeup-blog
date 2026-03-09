+++
date = '2026-03-04'
draft = false
title = 'Unbreakable 2025'
ShowToc = true
tags = ["ctf"]
+++

I didn't participate in this edition but as a way to prepare for the 2026 edition Unbreakable I decided to try solving the last edition's challenges by myself.

And another note, these are only what I could find still lying around on CyberEdu, a lot of the challenges I just couldn't find.

## Gambling Habbits

We get an image from a video game I identifies as DayZ, through reverse image search, on the map of Chernarus. 
From the image it looks like the house is near some powerlines and rails, and near a forest.

I looked for types of houses in this game and identified it as a [land_house_2w02](https://dayz.fandom.com/wiki/Houses?file=Land_House_2W02.png). 

All that's left now is finding one near a forest, railway and powerline. And it took me a bit to realize, since maps coordinates have two types, xxxx.xx and x.xx, I had to find an online map with the required format.

Took me a while but I finally found it (after trying 30 different houses) [here](https://dayz.xam.nu/#10665.00;13860.00;2). The coordinates were `Dobroye(1.29:0.03)NE` and the flag was `CTF{6acfb96047869efed819b66c2bab15565698d8295ca78d7d4859a94873dcc5ce}`.

## Silent beacon

Network challenge with bluetooth packets! I did some recon and found this [amazing source](https://www.botanica.software/blog/unraveling-the-bluetooth-enigma-extracting-the-flag-from-bsides-tlv-2022-ctf). This gave me a bit of context into what's happening and I investigated the sbc route.

I ran the command `tshark -r capture.pcap -d "btl2cap.cid==0x0043,bta2dp" -T json -x > data.json` as instructed. 

The problem though, was this weird pattern thing that was happening in the sbc_raw. 
![challenge-screenshot](sbc_raw.png#center). So I started inspecting the pcap further packet by packet and found some interesting OBEX put protocol transmissions, which is apparently related to the FTP, more exactly a way to upload files. And since the file has a name, `ttsmaker-file-2025-4-10-13-59-35.mp3`, this makes the whole thing more interesting.

![challenge-screenshot](obex.png#center)

I wanted to take the values of the obex bodies and then treat them as hex somehow. So I did a `tshark -r capture.pcap -T fields -e "obex.header.value.byte_sequence" -Y "obex.opcode==0x02" | grep -v "^$" > bytes.hex` to extract the content. 

Then, to achieve my grand idea, I used this command: `cat bytes.hex | tr -d '\n' | xxd -r -p > flag.mp3`. This removed the newlines between packet bodies, then used xxd reverse (turn hex into binary, and the `-p` was just a plain hex format, without offsets).

I am so mad because since I was using headphones my stupid kali machine didn't play audio and I thought I just didn't solve the challenge, since I couldn't hear anything, so I spent another full hour trying a bunch of different shit, but that *was* indeed enough to solve it.

I still ended up trying to use an audio transcriber, and it worked - [turboai](https://turboscribe.ai/transcript/6683341847105292515/flag). The flag was `ctf{32faf5270d2ac7382047ac3864712cd8cb5b8999511a59a7c5cb5822e0805b91}`, after turning the output from the audio transcript to lowercase and adding the curly brackets.

## og-jail

The hint says just write HELP but the server just replies "Oh no, you need help"... trying something like `print(1)` gives us this strange error:

![challenge-screenshot](jail1.png#center)

I looked it up on google and I found this Stack Overflow conversation:

![challenge-screenshot](jail2.png#center)

And sending it as a string works. But I'm pretty sure it's not what I was supposed to do.

![challenge-screenshot](jail3.png#center)

I also inspected the source, and an empty message by us would have given us "Invalid input, HELP or SOURCE for more information". And SOURCE would have given the b64 source code. The blacklist was just `['getattr','eval','lambda']`. 

So to understand why this works is to look into `literal_eval`: it's like a safety measure for `eval` that doesn't allow us to execute any commands, just send in strings, numbers, lists and so on. If it detects any function calling business, it throws an error.

So us sending a python command would crash there, as you saw. And what it returns is the corresponding python value for it. 

And doing `literal_eval('"hello"')` just returns the string `'hello'`, since it's a string, so that's valid, right? That's what's stored in `parsed` and then executed inside `eval` as a parameter. So that's why the exploit worked.

The flag was `ctf{97829f135832f37a4b3d6176227cf6b96d481d543e6051c0087f24c1cd0881ed}`. 


