+++
date = '2026-04-23'
draft = false
title = 'gef'
ShowToc = true
tags = ["Materials"]
+++


## Why

I've had this on my iPad for months but I think it's time I write some of this down on this blog as well.

## gef

[gef](https://github.com/hugsy/gef) (GDB enhanced features) *is a set of commands for x86/64, ARM, MIPS, PowerPC and SPARC to assist exploit developers and reverse-engineers when using old school GDB.*

The only reason I have gef instead of pwndbg is that when I tried to install pwndbg on my first ever kali machine, it wouldn't work, and gef took a minute or two to set up; And I've stuck with it ever since. [Cheatsheet](https://raw.githubusercontent.com/zxgio/gdb_gef-cheatsheet/master/gdb_gef-cheatsheet.pdf).

Bonus: Using `ropper` for gadgets: `ropper -f ./file --search "pop rdi; ret"`. Gadgets are in both libc and the binary.

---

1. Useful Stuff

- `start` instead of `run` - breaks after starting program

- `vmmap` - info proc mappings

- `search-pattern "/bin/sh"` - finds occurrences of a string

- `info functions "system"` - finds the address of a specific function

- `hexdump byte $rsp` - dump the address, 64 bytes.

- `CTRL+C` - break program

- `p/x <addres>` - print address as whatever

- `x/[nr][b(byte)/h(halfword)/w(word)][x(hex)/d(deci)/u(unsigned)/f(float)/c(chr)/s(str)/i(instr)/a(addr)] <addr>` prints it

2. Breakpoints

- `b * <address>`

- `info b`

- `enable/disable/delete <bp-id>`

- `c <ignore-count>` - skips n breakpoints

- `enable once <bp-id>` 

3. Watchpoints

- `watch * <address>` - watchpoint on write

- `awatch * <address>` - read/write watchpoint

- `rwatch * <address>` - read watchpoint

- `watch $rax == 0xfafa` - watchpoint on condition

- `info wat`

4. Stack

- `info frame` - stack frame

- `bt/backtrace` - trace of the previous stack frame

5. Pie

- `pie b <offset>` - breakpoint

- `pie run` 

6. Memory

- `set {c-type}<addr> = <val>` like `set {int}0x802040 = 4` - modify memory

- `set $y = 0x500000` - sets a variable (can be later printed the way registers are)

- `set $rax = 1` - modify register

- `find <start>, <end>, <data>` like `find 0x100, 0x400, "Hello"` - search memory

- `vmmap` - show mapping

Also:

`%1$p.%2$p.%3$p.%4$p.%5$p.%6$p.%7$p.%8$p.%9$p.%10$p.%11$p.%12$p.%13$p.%14$p.%15$p.%16$p.%17$p.%18$p.%19$p.%20$p.%21$p.%22$p.%23$p.%24$p.%25$p.%26$p.%27$p.%28$p.%29$p.%30$p.%31$p.%32$p.%33$p.%34$p.%35$p.%36$p.%37$p.%38$p.%39$p.%40$p.%41$p.%42$p.%43$p.%44$p.%45$p.%46$p.%47$p.%48$p.%49$p.%50$p.%51$p.%52$p.%53$p.%54$p.%55$p.%56$p.%57$p.%58$p.%59$p.%60$p.%61$p.%62$p.%63$p.%64$p.%65$p.%66$p.%67$p.%68$p.%69$p.%70$p.%71$p.%72$p.%73$p.%74$p.%75$p.%76$p.%77$p.%78$p.%79$p.%80$p.%81$p.%82$p.%83$p.%84$p.%85$p.%86$p.%87$p.%88$p.%89$p.%90$p.%91$p.%92$p.%93$p.%94$p.%95$p.%96$p.%97$p.%98$p.%99$p.%100$p.%101$p.%102$p.%103$p.%104$p.%105$p.%106$p.%107$p.%108$p.%109$p.%110$p.%111$p.%112$p.%113$p.%114$p.%115$p.%116$p.%117$p.%118$p.%119$p.%120$p.%121$p.%122$p.%123$p.%124$p.%125$p.%126$p.%127$p.%128$p.%129$p.%130$p.%131$p.%132$p.%133$p.%134$p.%135$p.%136$p.%137$p.%138$p.%139$p.%140$p.%141$p.%142$p.%143$p.%144$p.%145$p.%146$p.%147$p.%148$p.%149$p.%150$p`
