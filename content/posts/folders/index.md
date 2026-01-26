+++
date = '2026-01-26'
draft = true
title = 'Linux Folders'
ShowToc = true
tags = ["Materials", "web"]
+++


## Why

After a bunch of challenges involving LFI I got tired of having to guess where everything is every time; I realised I didn't know the file system structure that well, especially for ctf stuff, so here is some docs I made for myself.

Here is a [source](https://man7.org/linux/man-pages/man7/hier.7.html).

---

## Folders

Obviously, first, `/etc/passwd`. In `/etc/passwd` all the users with their home dirs and default shells are stored, like username:password:UID:GID:GECOS:home_directory:shell. This is good for groundlaying where we're going to be looking.

Next, the `/proc`. That's a virtual filesystem that tells us about processes and system resources. The `/proc/self` refers to the *current* running process. Let's look at each process' files:
 - `/proc/self/fd` is its file descriptors, aka all open file or I/O sockets;
 - `/proc/self/cmdline` is the command issued when starting the process (sth. like python3 app.py);
 - `/proc/self/cwd` is a symbolic link to the current working directory;
 - `/proc/self/environ` is a list of environment variables for the process;
 - `/proc/self/exe` is a symbolic link to the executable of the proc;
 - `/proc/self/maps` is a list of memory maps to the various exes or library files associated.

Then, `/var/www` or `/var/www/html` are the default root folders of web servers. 

Then, for apache, `/var/log/apache2/access.log` and `.htaccess`, nginx, `/var/log/nginx/access.log`, wordpress, `wp-config.php`.

[Here](https://d00mfist.gitbooks.io/ctf/content/local_file_inclusion.html) are a bunch of files to test.


