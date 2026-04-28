+++
date = '2026-04-01'
draft = false
title = 'Pico Irish Name Repo 1, 2, 3 Writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Challenge overview

Do you think you can log us in? Try to see if you can login!

---

Another super easy challenge.

## Irish Name Repo 1

Opening the request, we can see a "debug" parameter or whatever it's called, and it enables us to see our queries. I don't even think it was necessary since this was just the simplest form of SQLi.

![challenge-screenshot](flagh.png#center)

## Irish Name Repo 2

Same stuff

![challenge-screenshot](flag2.png#center)

## Irish Name Repo 3

Still basic SQLi, just that our text is being ROT13 encoded. So we pop that in ROT13 before that and we get the flag. 

![challenge-screenshot](rot.png#center)

![challenge-screenshot](flag3.png#center)
