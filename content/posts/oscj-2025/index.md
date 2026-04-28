+++
date = '2026-05-09'
draft = true
title = 'Simulare OSCJ 2026'
ShowToc = true
tags = ["ctf"]
+++

## Overview

Although my team didn't qualify for the finals this edition of Unbreakable, we still placed a decent score and since I enjoy making writeups I decided I'd make one anyways. Just as a heads-up, I will only include the ones that I personally solved.

![challenge-screenshot](scores.png#center)

Since we were only two members, it was a little tough on us, and I stayed up the entire last night, but it didn't really make up for the lack of manpower. And this really felt more like a project management competiton; who can get their three agents to do the fastest, efficient and most work.

I felt like almost *none* of these challenges were manageable without AI, but I do understand that making them palpable meant they could be solved in two prompts. Nevertheless, there were still some challenges that I enjoyed solving. 

Now, let's actually get into the challenges!

## biscuiti

![challenge-screenshot](top9.png#center)



---

The rest of the challenges were either solved by my teammate or completely by ChatGPT so that was it for this writeup. Thank you for reading until the end, and I'm glad if this can be of any help to anyone.

└─$ tshark -r task.pcap -T fields -e http.cookie -Y http | grep -o -e '[0-9].*' | sort -n | grep -o ....$ | tr --delete '\n' 
Y3Rme2FkYTAwYmZkNDRhMTYxM2M3YWI5MzM0NTk3MGY5ZjYwMWNhMDYxYmE5NjFkYmFjZmVhMGViZDAxZGUzMTQzZjV9 = ctf{ada00bfd44a1613c7ab93345970f9f601ca061ba961dbacfea0ebd01de3143f5}

##montgomery 

Enter your input: %73$p.%74$p.%75$p.%76$p.%77$p.%78$p.%79$p.%80$p.%81$p.%82$p.%83$p.%84$p.%85$p.%86$p.%87$p.%88$p.%89$p.%90$p.%91$p.%92$p.%93$p.%94$p.%95$p.%96$p.%97$p.%98$p.%99$p.%100
%73$p.%74$p.%75$p.%76$p.%77$p.%78$p.%79$p.%80$p.%81$p.%82$p.%83$p.%84$p.%85$p.%86$p.%87$p.%88$p.%89$p.%90$p.%91$p.%92$p.%93$p.%94$p.%95$p.%96$p.%97$p.%98$p.%99$p.%100
0x7c84ecb3e750.0x7c84ecb3e760.(nil).0x323136337b465443.0x6134333733343061.0x3836653630663532.0x3835333235393435.0x6435323739353236.0x3337336630363833.0x6461333961376264.0x3939356266393431.0x7d61383266.(nil).(nil).(nil).(nil).(nil).0x37252e7024333725.0x243537252e702434.0x2e70243637252e70.0x37252e7024373725.0x243937252e702438.0x2e70243038252e70.0x38252e7024313825.0x243338252e702432.0x2e70243438252e70.0x38252e7024353825.%100

Enter tangled string:2163{FTCa437340a86e60f5285325945d5279526373f0683da39a7bd995bf941}a82f
Enter chunks size (4 or 8 probably):8
CTF{3612a043734a25f06e68549523586259725d3860f373db7a93ad149fb599f28a} 

##silent-relay

read secrets from file; as binary.

if 0, sleep for 0.1 microseconds; if 1, sleep for 0,5 microseconds after sening. (sent from p12345 to 80)

in the packets sorting by tcp.srcport==12345 and [TCP Port numbers reused] then indeed its either 500milis or 100 milis.

last 160bits are corrupted? 

ctf{baf9eecbff31e3d0fcdf9dc820d673594261100b0556 e corect, deci da

->intr-adevar se pierde unul de la final; pt ca pauza. 

##mlue

tcp stream 9, mblue-lockerV1, apoi ps e trimis de un port de pe 127.0.0.1 care apoi trm la 9001. si el e cel care a scris ps

first, compara cu OSC{m4st3rz
