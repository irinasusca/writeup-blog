+++
date = '2026-02-01'
draft = false
title = 'Wireshark, tshark & sorting'
ShowToc = true
tags = ["Materials", "web"]
+++


## Why

Since this is, sadly, something that needs to be done in order to score points in ctfs, I'm going to cover some things that *I* feel  are important in this category. 

I have done quite a few forensics challenges, but I never really mastered `grep` and `tshark` to their full potential. And I forgot most of my Wireshark expertise from last year, so I'll include what I feel is important or non-intuitive about that as well.

---

I'm writing this as I learn, so keep that in mind.

## Grep

Feel free to skip this if you already know your stuff with grep. I for one always avoided learning this in depth, so that's what I'll be doing now.

We all know the basic syntax, `grep "string" /path/file`. There is also the color-text-in-file `--color` parameter.

To ignore case sensitivity, just add an `-i` before the string. 

To just count the lines in which the text appears, `-c`. If you want to see them *and* number them, use `-n`.

To invert the grep output, add a `-v`; this means print all the lines that *don't* contain the expression. 

For an exact word, use `-w`, meaning it won't print a word if it's a suffix/prefix. 

If we only want the matches, and not the lines, add an `-o`.

Obviously the most useful grep is, is as a pipe. So if we want to see if openSSH has been installed on our system, we can just do `dpkg -L | grep -i "openssh"`.

The `-A 4` will print the line with our string and then 4 more lines coming after, and `-B 4` the string and its 4 preceding lines (you know, after, before..).

Now time for REGEX (REGular EXpressions)! A REGEX is a sequence of characters that is used to match a pattern. 

To search for an expression, we add an `-E` (for example, looking for `first|second`, looking for either words).

The `^ ` and ` $` are used as anchors; `^c` means line begins with `c`, and `c$` means line ends with `c`.

The dot `.` is a one character wildcard, meaning any character. If you mean the *actual* dot, escape by using a `\` like `\.`.

The full wildcard is `*`, can also be used for files, like `*.txt` means look in all files with that extension.

If instead of a wildcard, we mean to search a certain range, we use the `[..]` syntax. An example is `grep -w '[sS]ample[0-9]' file`. We can also use `[A-Za-z]` for letters. If we want to *negate* a range, we can use a `^` as in `[^0-9]`.

If we want an AND, we just pipe the output through another grep.

We can also test how many times a character must be repeated in a sequence, with `{N}`. This can also be a range, like `{min,max}`. For example, to match both *col* and *cool*, we can use `grep -E 'co{1,2}l' file`. If we don't specify a maximum, like `{N,}`, it means *at least* N characters.

A useful source I used was [this](https://www.cyberciti.biz/faq/grep-regular-expressions/).

## Sort

Now a word about using `sort` because I came across this in a challenge and had to resort to ChatGPT to do it, and we can't have that. Just using `sort filename` sorts the lines alphabetically.

Now let's look at the flags. `-r` for reverse order, `-n` to sort numerically, `k` to sort based on a specific column number, `-u` to remove duplicates. 

`-t` specifies a delimiter for fields, which if unspecified, is automatically space. And `-k1` means from field 1 to end of line while `-k1,1` means to only use that one field.

# Sed

Turns out `sed` (stream editor) is quite important as well. The source I'll be referencing is [here](https://dev.to/eshanized/mastering-sed-commands-and-flags-a-guide-to-stream-editing-in-linux-29jj).

1. **Substitution**: `sed 's/pattern/replacement/flags' file` - Replace the first occurrence of pattern with replacement. Some flags are:

 - `sed 's/foo/bar/g' file.txt` for global substitution (all of them); 

 - `sed 's/foo/bar/i' file.txt` is case insensitive search;
 
 - `sed 's/foo/bar/2 file.txt` replaces the n-th occurrence of foo with bar (in this case, 2).
 
 2. **Deletion**: `sed '/pattern/d' file`.
 
 - To delete blank lines for example, we can do `sed '/^$/d' file.txt`.
 
 - To delete all lines starting with a digit, just like grep, `sed '/^[0-9]/d' file.txt`.
 
 3. **Printing**: We can print lines matching a pattern, often with `-n` as a flag to suppress the normal behaviour of sed which just prints everything: `sed -n '/pattern/p' file`.
 
 - To print matching lines with the next line, `sed -n '/error/{N; p}' file.txt`. This prints lines containing error along with the following lines.
 
 4. **Insertion**, to add a line before the pattern-found-line: `sed 'line_number i\text_to_insert' file`.
 
 - To insert text before a specific line, `sed '2i\I'm inserted before line 2' file`.
 
 - To insert text before a specific pattern, `sed '/error/i\Next is an error message.'`
 
 5. **Appending**: Just like insert, but it's just after: `sed 'line_number a\text_to_append' file`.
 
 - To append text after a specific line, `sed '2a\I'm after line 2' file.txt`.
 
 - To append text after a specific pattern, `sed '/error/a\I'm after an error' file.txt`.
 
 6. **Change**: Just modify the entire content of a line with new text: `sed 'line number c\new_text' file`.
 
 - To change the content of a certain line: `sed '2c\Now I am line 2' file`.
 
 - To replace all matching lines of a pattern: `sed '/error/c\Critical Error' file.txt`. This replaces all lines containing error to Critical Error.
 
 7. **Ranges**: We can apply sed to a range of lines, too: `sed 'start_line, end_line command' file`.
 
 - For example, to delete lines 2 to 4: `sed '2,4d' file`.
 
 - To delete text between the first two occurrences of patterns: `sed '/start/,/end/d` - removes all text between and including the first start and end.
 
---
 
We can chain multiple commands, sequentially, using `-e`. And as I meantioned, by default, sed prints every line, and the `-n` flag blocks this. The `-i` flag enables in-place editing aka it modifies the file directly; otherwise, it needs redirection, it doesn't actually modify our file. And of course like grep, to use RegEx, we need to add the `-E` flag. And to escape special characters of course we use `\`.

## Find

Also a useful command in some challs was `find`, to search system-wide for files containing "ctf" like `sudo find / -type f -exec grep -l "ctf" {} + 2>/dev/null`. Or maybe like `grep -RIl "ctf" / 2>/dev/null`.
 

## Wireshark

Now that we have a basic understanding of grep, before we get to the more intimidating tshark, let's note a few things about Wireshark. [Source](https://book.jorianwoltjer.com/forensics/wireshark) if you don't like how I said it.

```bash
tcp.port == 4444  # Match TCP port
ip.addr != 10.10.10.10  # Filter out source or destination IP address
eth.addr == 00:00:5e:00:53:00  # Filter Ethernet MAC address
http  # Filter only http traffic
http.host contains "example"  # Filter HTTP host header containing string
pkt_comment  # Filter on Wireshark comments in the capture
```

We can use `||` `&&` `==` and `!=` normally.

The most important filters are:

 - `tcp` (inlcudes http). We can follow streams (formed by multiple packets).
 
 - `http` which is self explanatory, isn't it? To download files sent over http, we can look at `File -> Export Objects -> HTTP` to view all objects and download what we like.
 
 - `dns` 
 
 - `USB Keystrokes`, like a USB keyboard for example, sending a lot of `URB_INTERRUPT in` packets. 
 
 - `SSL/TLS` (transfer layer security, so https) means we need a RSA key to decrypt the data. We can go to `Edit -> Preferences -> Protocols -> TLS` and add an entry with the IP and port of target, the http protocol and the path to the file containing the key. 

## tshark

Terminal wireshark. Useful for extracting stuff quickly. This is how our parameters will look like: 

- `-r` - .pcap to read from

- `-Y [filter]` - filters to apply

- `-T fields` - display only selected fields

- `-e [field]` - field name to display

We can view the field name clicking on it in Wireshark. I really did think this would be more complicated, but that's kind of it.

I made a challenge to demo my new knowledges [here](), so you can take a look at that if you want.
