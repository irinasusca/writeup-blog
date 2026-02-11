+++
date = '2026-02-03'
draft = false
title = 'CyberEdu biscuiti Writeup'
ShowToc = true
tags = ["CyberEdu", "network"]
+++

## Challenge overview

Biscuiții mei au prea multe calorii, așa că trebuie să îi împart în mai multe porții.

În această probă, aveți o captură PCAP, iar obiectivul este să recuperați un secret.

---

I already solved this last year at the OSCJ but the foolish way, looking through pcaps like a fool. But *now*, we're solving this with tshark!

---

The command I used was `tshark -r task.pcap -Y http -T fields -e http.cookie_pair` to print out all of the cookie parts, along with their indexes. But then I thought, what the hell, if I'm not doing that manually, I'm not doing anything manually! So I came up with this command:

`tshark -r task.pcap -Y http -T fields -e http.cookie_pair | sort -t= -k2,2n | grep -o '[a-zA-Z0-9]\{4\}$' | base64 --decode` 

which immediately prints out the flag. It sorts them based on index (`-t=` means split into tokens based on `=`, and sort based on the `2,2` as in min-max `n`umerically.), grabs all the end base64 parts with `-o` so just the pattern, not the line, and base64 decodes it. And boom!

![challenge-screenshot](flag.png#center)

That's it!





