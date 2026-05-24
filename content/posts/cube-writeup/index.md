+++
date = '2026-05-13'
draft = false
title = 'Dreamhack cube Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
드림이가 오랜만에 도서관에 왔습니다! 원하는 책을 읽어볼까요?
플래그는 /home/pwnlibrary/flag.txt에 있습니다.

---


```c
void menuprint(){
	printf("1. borrow book\n");
	printf("2. read book\n");
	printf("3. return book\n");
	printf("4. exit library\n");
}
```

```c
int steal_book(){
	FILE *fp = 0;
	__uint32_t filesize = 0;
	__uint32_t pages = 0;
	char buf[0x100] = {0, };
	printf("[*] Welcome to steal book menu!\n");
	printf("[!] caution. it is illegal!\n");
	printf("[+] whatever, where is the book? : ");
	scanf("%144s", buf);
	fp = fopen(buf, "r");
	if(!fp){
		printf("[*] we can not find a book...\n");
		return 1;
	} else {
		fseek(fp, 0, SEEK_END);
    	filesize = ftell(fp);
    	fseek(fp, 0, SEEK_SET);
		printf("[*] how many pages?(MAX 400) : ");
		scanf("%u", &pages);
		if(pages > 0x190){
			printf("[*] it is heavy!!\n");
			return 1;
		}
		if(filesize > pages){
			filesize = pages;
		}
		secretbook.contents = (char *)malloc(pages);
		memset(secretbook.contents, 0x0, pages);
		__uint32_t result = fread(secretbook.contents, 1, filesize, fp);

		if(result != filesize){
			printf("[*] result : %u\n", result);
			printf("[*] it is locked..\n");
			return 1;
		}
		
		memset(secretbook.bookname, 0, 0x20);
		strcpy(secretbook.bookname, "STOLEN BOOK");
		printf("\n[*] (Siren rangs) (Siren rangs)\n");
		printf("[*] Oops.. cops take your book..\n");
		fclose(fp);
		return 0;
	}

}
```
## Identifying the vulnerabilities

The secret option to steal a book is `275`.

This is the memory layout in .bss:

```asm
.bss:0000000000004040                 public listbook
...
.bss:0000000000004CC0 booksize        dd ?                    ; DATA XREF: borrow_book+1C↑r
.bss:0000000000004CC0                                         ; borrow_book+8F↑r ...
.bss:0000000000004CC4                 align 20h
.bss:0000000000004CE0                 public secretbook
.bss:0000000000004CE0 secretbook      dq ?                    ; DATA XREF: steal_book+342↑o
```

At `0x10` after `booksize` is going to be the content of our secret stolen book.

This is how `borrow_book()` looks like:

```c
int borrow_book(){
	if(booksize >= 0x50){
		printf("[*] book storage is full!\n");
		return 1;
	}
	__uint32_t select = 0;
	printf("[*] Welcome to borrow book menu!\n");
	booklist();
	printf("[+] what book do you want to borrow? : ");
	scanf("%u", &select);
	if(select == 1){
		strcpy(listbook[booksize].bookname, "theori theory");
		listbook[booksize].contents = (char *)malloc(0x100);
		memset(listbook[booksize].contents, 0x0, 0x100);
		strcpy(listbook[booksize].contents, "theori is theori!");
	} else if(select == 2){
		strcpy(listbook[booksize].bookname, "dreamhack theory");
		listbook[booksize].contents = (char *)malloc(0x200);
		memset(listbook[booksize].contents, 0x0, 0x200);
		strcpy(listbook[booksize].contents, "dreamhack is dreamhack!");
	} else if(select == 3){
		strcpy(listbook[booksize].bookname, "einstein theory");
		listbook[booksize].contents = (char *)malloc(0x300);
		memset(listbook[booksize].contents, 0x0, 0x300);
		strcpy(listbook[booksize].contents, "einstein is einstein!");

	} else{
		printf("[*] no book...\n");
		return 1;
	}
	printf("book create complete!\n");
	booksize++;
	return 0;
}
```

Each `booksize` entry consists of a `bookname` and `contents` pair.

Here is `read_book`:

```c
int read_book(){
	__uint32_t select = 0;
	printf("[*] Welcome to read book menu!\n");
	if(!booksize){
		printf("[*] no book here..\n");
		return 0;
	}
	for(__uint32_t i = 0; i<booksize; i++){
		printf("%u : %s\n", i, listbook[i].bookname);
	}
	printf("[+] what book do you want to read? : ");
	scanf("%u", &select);
	if(select > booksize-1){
		printf("[*] no more book!\n");
		return 1;
	}
	printf("[*] book contents below [*]\n");
	printf("%s\n\n", listbook[select].contents);
	return 0;
}
```

So we want a way to read our stolen book. Looks like a UAF.

If we get a book, and free it, when we steal a book it's going to get malloc-ed in its place, if it's the right size. Then, since `return_book` doesn't clear the booksize after freeing, we should still be able to print it. That would lead to secret book getting printed, since it's going to be at the place where book 0 used to be.

I tried with the pages set as 20 at first, but our secret flag didn't get malloc-ed in the right place. I checked in `pwndbg`, looked at the bins, and found that the tcache still pointed to the freed first book, and secret book got allocated from the top chunk:

```bash
pwndbg> x/20gx 0x555555554000 + 0x4040
0x555555558040 <listbook>:      0x7465722d2d2d2d2d      0x2d2d2d64656e7275
0x555555558050 <listbook+16>:   0x0000000000002d2d      0x0000000000000000
0x555555558060 <listbook+32>:   0x0000555555559720      0x0000000000000000
0x555555558070 <listbook+48>:   0x0000000000000000      0x0000000000000000
0x555555558080 <listbook+64>:   0x0000000000000000      0x0000000000000000
0x555555558090 <listbook+80>:   0x0000000000000000      0x0000000000000000
0x5555555580a0 <listbook+96>:   0x0000000000000000      0x0000000000000000
0x5555555580b0 <listbook+112>:  0x0000000000000000      0x0000000000000000
0x5555555580c0 <listbook+128>:  0x0000000000000000      0x0000000000000000
0x5555555580d0 <listbook+144>:  0x0000000000000000      0x0000000000000000
pwndbg> bins
tcachebins
0x110 [  1]: 0x555555559720 ◂— 0
0x1e0 [  1]: 0x555555559830 ◂— 0
0x410 [  1]: 0x555555559310 ◂— 0
```

But, look at that size!! 0x110! I tried again, this time with the pages set to 256 (0x100). It worked! Printing the book 0 got us the flag!

Let's finish writing the exploit and getting the flag.

![challenge-screenshot](flag.png#center)


---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/master_canary.py)**.
