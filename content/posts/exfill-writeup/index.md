+++
date = '2026-02-13'
draft = false
title = 'CyberEdu exfill - very funny Writeup'
ShowToc = true
tags = ["CyberEdu", "network"]
+++

## Challenge overview

Extract the flag from the pcap.

---

This challenge is just a bunch of GET requests, from /page0 to /page9 of something about Chunk Norris. 

I sifted through a bunch of the HTTP requests and the only thing that seemed to change irregularly was the `http.user_agent`: It looked like `User-Agent: curl/0 00 0 0 0`, with the 0s and spaces alternating seemingly randomly. I thought that might be a binary code throughout the million requests, with the spaces having to be FILLED with 1s (you know, since the name is exFILL) but it turned out to be a bunch of gibberish. 

I even tried to xor it, same stuff. 

---

I had to practice for my theoretical driving exam so I had to put off this challenge for a couple of days so I just looked up a writeup for it, and I was close noticing the User Agent but it's a little more complicated than that.

## The solution

Turns out this was solvable with a decabit (you know, ten bits) lookup table. So what I should have done is looked online for 10 bit types of encryption. [Here it is](https://www.dcode.fr/decabit-code).

---

BUT! Before the decabit, we have a Chuck Norris encoding which is GREATLY referenced in the chall. Whoops, missed that one. Pretty interesting though;

![challenge-screenshot](chuck.png#center)

So the first command I ran was `tshark -r captura.pcapng -Y 'http&&ip.src==192.168.124.1' -T fields -e 'http.user_agent' | grep -E -o  '.{10}$' | tr -d '\n'` to extract all the user agents without the newline, and put that through this [Chunk Norris decoder](https://www.dcode.fr/chuck-norris-code).

![challenge-screenshot](decode.png#center)

Just *now* comes that decabit into play. This part I couldn't have guessed, genuinely. Putting that into a decabit, we get the flag reversed.

![challenge-screenshot](deca.png#center)

So we just reverse that and the flag is `ctf{b3d7630e73726a79f39210a8c5e170aa1da595404aacbf0c765501c8c3257e5b}`. 

## How though?

But I was still wondering how the hell you're supposed to reach the conclusion that that is, in fact, decabit. So first I threw them into ChatGPT, Deepseek, Claude and Gemini.

I don't know *what* Claude thought I was doing but it flagged the chat.

![challenge-screenshot](claude.png#center)

Gemini just hallucinated some lorem ipsum:

![challenge-screenshot](gemini.png#center)

Deepseek just entered a C-printing loop:

![challenge-screenshot](deepseek.png#center)

But ChatGPT was *by far* the worst one:

![challenge-screenshot](chatgpt.png#center)

And the dcode.fr cipher detector didn't say shit about it being decabit. *Even though* it is capable of decoding decabit from 0s and 1s and even C's and N's instead of just + and -. 

This other website [cachesleuth's cipher detector](https://www.cachesleuth.com/multidecoder/) showed everything but since it only recognized + and - it didn't show up.

But it did prompt us to add the characters as keys - and here it is - decoded!

![challenge-screenshot](human.png#center)

This did give me an idea for [this tool]() though.

So indeed it was solvable. I'm just glad I found this website now! Thanks for reading!
