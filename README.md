# CTF-2020
### [ROP EMPORIUM](#rop)

> #### [Ret2Win 64 bit](#ret2win)





## ROP EMPORIUM<a name="rop"></a>

***

### RET2WIN64<a name="ret2win"></a>

For this first challenge

![First image](https://github.com/jpowellroot/CTF-2020/blob/master/2-1.png?raw=true)

##### payload

~~~ python
#/usr/bin/env python

from pwn import *

context.clear(i386)
context.log_level = 'debug'


~~~
