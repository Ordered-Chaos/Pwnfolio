~~~python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#=========================================================
#                   SETTING UP VARIABLES
#=========================================================

os ='linux'
arch ='i386'    
r_host = '2019shell1.picoctf.com'
r_dir = ''
r_user = 'Intrinsic'
r_passwd = 'Kanoa2019'
#r_port = ''                                            
exe = 'binary name'
argv = sys.argv
gdbscript = 'b* main'

                  # Environment variables # 

context.log_level = 'info'
context.update(os=os, arch=arch)

#==========================================================
#                   FUNCTION DEFINITIONS
#==========================================================

def attach_gdb():
        gdb.attach(io, gdbscript=gdbscript)

def start(argv=[], *a, **kw):
    if args.gdb:
        global elf = context.binary = ELF(exe)
        global io = process(elf.path)
        global context.log_level = 'debug'
        attach_gdb()
        log.info('Setting log level to %s', str(context.log_level))
        log.info('Attaching gdb to running process')
        log.info('gdb script = %s', str(gdbscript))
        log.info('Starting debug exploit...')

    elif args.remote:
        global context.log_level = 'error'
        global s = ssh(host=r_host, user=r_user, password=r_passwd)
        global elf = exe
        global io = s.process(elf, cwd=r_dir)
        log.info('Remote variables set:')
        log.info('Remote host = ', str(r_host))
        log.info('Remote user = ', str(r_user))
        log.info('Changing working directory to: ', str(r_dir))
        log.info('Starting remote exploit...')

    else:
        global elf = context.binary = ELF(exe)
        global io = process(elf.path)
        log.info('Starting local exploit ...')

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

io.interactive()

#===========================================================
#                       
#===========================================================
~~~