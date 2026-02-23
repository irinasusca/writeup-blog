+++
date = '2026-02-18'
draft = false
title = 'CyberEdu badimg Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++


## Challenge overview

Web apps are everywhere, so are the bugs.

---

This is an image upload injection with php.

## Identifying the vulnerabilities

[First some recon about this sort of vulnerability](https://portswigger.net/web-security/file-upload).

The files we upload are saved in `/profiles/longcode.jpg` (rendered as jpg) but also available at `/index.php/page=profiles/longcode.jpg` (rendered as html) even if their extension is php.

I tried a bunch of tricks including adding a php command as an exiftool comment, but it doesn't get rendered on the page. And somehow, our file gets longer. But something's weird here.

![challenge-screenshot](weird.png#center)

The *preview* file is the one getting rendered, and something is just overwriting our comment here.

![challenge-screenshot](files.png#center)

That something is that our file is getting compressed and the metadata is getting overwritten by `CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), default quality.`. As I was writing this I was scrolling like, the fifth? Maybe? Website about file injection and extremely luckily - In this [website](https://onsecurity.io/article/file-upload-checklist/) - 

![challenge-screenshot](aha.png#center)

EXACTLY what we're fighting with! I tried working with this but guess what, that script was made in 2009. So we need to patch a bunch of shit. And turns out gifs aren't even supported. I stumbled upon [this other writeup for some other ctf challenge](https://platypwnies.de/writeups/2025/gpn/web/image-contest/) and since PNG aren't supported in this chall, I tried their PoC for jpegs, but it didn't work.

![challenge-screenshot](lfi.png#center)

And I just now realized we had lfi this whole time. So if we can somehow find where our files are getting stored at, maybe we can open them and run that god damn php. 

---

I took a break from this as I got really sick, I even tried looking for the writeup online but I didn't find one so I took it as a sign to solve this myself. I found [this](https://github.com/fakhrizulkifli/Defeating-PHP-GD-imagecreatefromjpeg/blob/master/README.md) resource and FINALLY WE EXECUTE PHP!

![challenge-screenshot](run.png#center)

So essentially the vulnerability is injecting php code after the Scan Header. What is the Scan Header you might ask yourself? Well it signals the end of metadata and beginning of the actual image data.

![challenge-screenshot](scan.png#center)

But we soon bump into another problem, the fact that any command execution returns a 500 from the server or a 200 without the php being executed, ending up completely scrambled through the compression. And the reason was right under my nose, I realised half an hour later:

![challenge-screenshot](blaclist.png#center)

All we need though is a way to do some sort of `ls`. I spent *another day* doing and trying things I won't even get into and I resorted to a little help from ChatGPT who suggested this function: `<?=join(',',glob('/*'))?>`.

It was a great one because it was both short *and* safe I suppose.

![challenge-screenshot](flag1.png#center)

And now we can just retrieve the god damn flag.

![challenge-screenshot](flag2.png#center)

---

Just as a fun fact this stupid challenge took me about a week

