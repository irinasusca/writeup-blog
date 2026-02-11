+++
date = '2026-02-05'
draft = false
title = 'CyberEdu packet-snatchers Writeup'
ShowToc = true
tags = ["CyberEdu", "network"]
+++

## Challenge overview

Get ready for a multi-protocol, multi-question hunt

---

I'll just include the answers and maybe some other things I thought were slightly more difficult than the others.

---

I took the FTP command list from [here](https://en.wikipedia.org/wiki/List_of_FTP_commands).

The command to print out all the files downloaded by ftp, alphabetically: `tshark -Y ftp -T fields -e ftp.request.arg -r traffic.pcap | sed '/^$/d' | sort -u`.

Here are the question asnwers:

![challenge-screenshot](pic1.png#center)

![challenge-screenshot](pic2.png#center)

That's it!





