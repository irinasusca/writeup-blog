+++
date = '2026-05-05'
draft = false
title = 'Volatility'
ShowToc = true
tags = ["Materials"]
+++


## Why

Although I don't necessarily like forensics challenges, it's about time I learned to use Volatility, the most well known tool for memory forensics.

## About

There are two versions of Volatility:

- **Volatility**, the "classic" 2.7 python version compatible, that I am still mentioning since it has some plugins that aren't available on the newer version and it's maintained its relevance. You will need a python2 venv for this though, using [pyenv](https://irinasusca.github.io/writeup-blog/pyenv). 

- **Volatility3**, the newer version running python 3.x. While you need to specify the profile of the memory dump, but this version does this by itself. 

Anyways, the takeaway you should get from this is that you should install both. 

## Usage

I'll just be talking about Volatility3 for now. We can do a bunch of stuff with Volatility. Like:

- Dump the process list: `python3 vol.py -f /path/dump_new.raw -o "dump" windows.pslist`. This displays all the processes that were running on the image.
