+++
date = '2026-01-04'
draft = false
title = 'VMs'
ShowToc = true
tags = ["chat", "vm"]
+++


## Why

I decided to make a post about VMs and things that I didn't see people talk much about, especially because of my past *experiences* with them. I will be talking about Windows *and* Linux machines, what worked for me and what didn't, how to set up and all that crap.

---

## Windows 

My first attempt at a "cybersecurity" Kali VM was on [Oracle VirtualBox](https://www.virtualbox.org/wiki/Downloads), on my old Windows Laptop (with 16GB of ram and 400GB of space), which didn't leave much for the VM, maybe four cores and 8GB RAM at best. 

And it was honestly a miracle I didn't quit because of it altogether, because it *constantly*, and I mean *constantly* crashed, the CPU usage was always trough the roof, I could hardly open a couple tabs of Firefox at once, let alone run brute force scripts. Even normal exploits, there was a 20% chance the VM would just crash and not save anything. Really annoying. Especially considering the CyberEdu website, which eats so, so, so many resources for some reason, and it freezes every other minute.

What made me really *have* to change though, literally, was that after installing a VPN my mouse cursor just disappeared. Something with xfce and gnome incompatibilities. But because it's Kali, there was no fix, I struggled with finding one for a week then I just started accepting it, because I had too much important stuff installed to make a new VM and start over. I really just started learning shortcuts for everything (which I actually use now, so maybe it wasn't that shit of a thing), and I used my VM mouseless for a month until I got a new laptop.

[Here's the documentation for Kali on VirtualBox if you need it.](https://www.kali.org/docs/virtualization/install-virtualbox-guest-vm/)

Maybe another solution is the [VMware](https://www.vmware.com/), I had a Windows VM on both VirtualBox and VMware on the same windows Laptop, and the VMware worked staggeringly better (still couldn't run games too well, maybe 20-30 fps, but it wouldn't instantly crash the VM when I ran them, unlike VirtualBox). So you might have more success with that one, but I recall it being a bit harder to install.

---

## Linux

Since those dark, dark days I've got myself a Thinkpad with 32GB RAM and an actual CPU, using Ubuntu because Windows 11 sucks. I just installed kvm, and I'm using the virt-manager's GUI. 

At first I gave it the same amount of RAM and cores as my old VirtualBox machine and it unironically worked miles faster, no delay when typing, instant connections, even firefox. But it still crashed and froze a few times, and I could tell I needed a bit more, so I moved to 12GB of ram and gave it 6 cores.

![challenge-screenshot](mem.png#center)

![challenge-screenshot](cpu.png#center)

You *do* need to install the spice tools for copy and paste between your main machine and VM though, so don't forget to do that. 

This has been the best experience I've had so far VM-wise, and the one I recommend the most. 

---

## Kali?

I know some people who don't use kali and some don't even use VMs, but you might install something that just makes your entire machine unusable and reinstalling a VM is easier than an entire laptop. And fair point, kali is a pain to use especially for beginners, and installing stuff and troubleshooting can be literally impossible *sometimes*. But most of the time it's fine, it has the most tools you will need built in, and it's what I've always used. 

But the most important thing is to know what you like the most and what you use the most efficiently, because if you're not comfortable with a distro nobody is forcing you to use it. So just do what makes you happy, or the least annoyed.

