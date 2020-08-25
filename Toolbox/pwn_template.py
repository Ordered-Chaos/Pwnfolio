#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#=========================================================
#                   SETTING UP VARIABLES
#=========================================================

os ='linux'
arch ='i386'    
# r_host = '2019shell1.picoctf.com'
# r_dir = '/problem/some_directory'
# r_user = 'User'
# r_passwd = 'XXXXXX'
# r_port = ''                                            
exe = './binary_name'
argv = sys.argv
gdbscript = 'b* main'
s = ''
io = ''
begin = ''
end = ''
data = ''

                  # Context variables # 

context.log_level = 'info'
context.update(os=os, arch=arch)

#==========================================================
#                   FUNCTION DEFINITIONS
#==========================================================

def attach_gdb():
        gdb.attach(io, gdbscript=gdbscript)

def start(argv=[], *a, **kw):
    global begin
    global exe
    global io
    global s
    begin = time.time()
    if gdb:
      io = process(elf.path)
      context.update(log_level = 'debug')
      attach_gdb()
      log.info('Setting log level to %s', str(context.log_level))
      log.info('Attaching gdb to running process')
      log.info('gdb script = %s', str(gdbscript))
      log.info('Starting debug exploit...')

    elif remote:
      context.update(log_level = 'error')
      s = ssh(host=r_host, user=r_user, password=r_passwd)
      io = s.process(elf, cwd=r_dir)
      log.info('Remote variables set:')
      log.info('Remote host = ', str(r_host))
      log.info('Remote user = ', str(r_user))
      log.info('Changing working directory to: ', str(r_dir))
      log.info('Starting remote exploit...')

    else:
      io = process(elf.path)
      log.info('Starting local exploit ...')

def finish():
  global end
  global begin
  end = time.time()
  print('Time elapsed: ', end - begin)

# Wwapper function in progress for 'recv()' to prevent hangs if no data received 
# def get_data():
  #global s
  # global data
  # Try:
    # data = s.recv()
    # print(repr(data))
  # except:
    # print('No data received')
    
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

# io.interactive()

finish()
#===========================================================
#                       
#===========================================================
