+++
date = '2026-04-23'
draft = false
title = 'Fix binary version'
ShowToc = true
tags = ["Materials"]
+++


## Why

I keep bumping into this stupid problem with binaries, where they provide the libc, but not the ldd. That means you can't run it locally using it. So you need to manually look for the stupid thing. And every time this happens I forget how to do it.

## Find the version

`strings libc-2.27.so | grep "GNU C Library"`

> GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.6) stable release version 2.27.

## Use a tool to pull the version

Get this tool:

```bash
git clone https://github.com/matrix1001/glibc-all-in-one
cd glibc-all-in-one
```

In this case, what I actually needed was `2.27-3ubuntu1_amd64`.

```bash
bash download 2.27-3ubuntu1_amd64
```

Now, in the `libs/` folder, we can find all we need. So, just patch the binary (run this in its folder):

```bash
patchelf --set-interpreter /home/kali/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so ./gauntlet
patchelf --set-rpath /home/kali/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 ./gauntlet
```

I had a bunch of zombie processes of it open, so I also ran this to kill them before:

```bash
pkill -9 gauntlet
pkill -9 gdb
```

Success!

![challenge-screenshot](yay.png#center)

That's it! You're good to go! Good luck!!!
