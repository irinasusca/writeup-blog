+++
date = '2026-02-06'
draft = false
title = 'CyberEdu usualtraffic Writeup'
ShowToc = true
tags = ["CyberEdu", "network"]
+++

## Challenge overview

Just normal network traffic. Or isn't it?

---

The correct way to phrase it would have been *Or is it?*, because the affirmation before isn't a negation. *Or isn't it?*

I noticed something weird following a TCP stream, at the last 4 bytes of each BGP update message packet.

The following command: `tshark -Y 'tcp.stream==1&&bgp.type==2&&ip.src==10.10.10.251' -r  traffic.pcapng -x | grep -o '\.d ....$' | grep -o ' ....$' | tr -d '\n'` outputs ` Hell o Ro uter 1!.H ere  is t he v ecto r: 8 BF46 C25D 9BAD 98ED 8EAE 6C1F 7AD2 D04. This  is  my s ecre t: u WyYT CYqB Ty9a fI69 to3e K0Sc CA3S lPDE zBsW BnR9 D8Ro 7aIO qihG MPXw u/Z+ HLn. `.

Changing ip.src to ip.dst in that command gives us `Hell o Ro uter  2   !.He re i s th e ke y: 7 4C95 6040 4342 7F0B EE1D 0E16 BFA5 3AFD 537F 736A D007 3C4C C4E1 CCB3 A82B 5DC. This  is  my s ecre t: K Q6R5 0gkQ LYCk Y90y IBDH DznH RUyM aTij WmHO 30UX jwft OMIG gZJh Kh2x li7S qln.`

From here on out I had no idea what to do, because this was a crypto challenge. So I had to look for an answer, and I found one. This is AES CBC!

But since we're not animals we're not writing any python to decode that. Instead, we're going to use one of the many free online tools at our disposal.

![challenge-screenshot](aes.png#center)

And the full flag is ... I forgot to write it out and I can't be bothered to fetch it from the chall, so, good luck with that.





