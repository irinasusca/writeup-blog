+++
date = '2026-02-10'
draft = false
title = 'CyberEdu universal-studio-boss-exfiltration Writeup'
ShowToc = true
tags = ["CyberEdu", "network"]
+++

## Challenge overview

Another Unbreakable tutorial whatever challenge. This time it's USB.

---

My tshark displays the usbhid.data as `1020304050607080` instead of `10:20:30:40:50:60:70:80`. And that's a thing that happens. I found this [writeup](https://medium.com/@alyangulzar149/how-to-solve-wireshark-usb-packet-data-challenges-in-ctfs-snyk-ctf-428302d9eb4d) for generally extracting USB data with [PUK](https://github.com/syminical/PUK#). 

I ran this command: `tshark -r task.pcap -Y 'usb' -T fields -e 'usbhid.data' | sed '/^$/d' | grep -v '0000000000000000' > capdata.txt` and replaced the capdata.txt in that repo, git cloned and ran PUK, and got the password `Yu=6SD6mvD9dU!9B`. 

Doing a `binwalk -Mve --dd=".*" task.pcap` leaves us with an encrypted flag.txt file to which we have to password. 

And here it is:

![challenge-screenshot](flag.png#center)

---

I know most of my flags were usually skillfully redacted but at this point I really can't be bothered to anymore.



