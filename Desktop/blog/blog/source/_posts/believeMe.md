---
title: believeMe
categories:
- noxCTF
---
#
noxCTF--believeMe

##
漏洞分析

文件放在IDA里一键F5，找到main函数，提示输出之后一个fgets最多可以输入39个字节，在输入字符串的末尾补\x0，用户的输入直接作为printf的参数，这里是格式化字符串漏洞，可以造成地址任意写。后面的canary保护导致不能随便溢出，在这里以printf为突破口

![main](./1.jpg)

##
漏洞利用

程序中有个函数叫noxFlag，里面是读flag的函数，因此只要控制eip跳转到这里即可。printf利用时可以用覆盖got表，也可以用覆盖返回地址的方式。在这里首先尝试覆盖返回地址。

断点下在printf，第一次的输入字符为'AAAA'+'%p'*17+'AA'，在Gdb中find 0x41414141找到AAAA所在的地址，再使用fmtarg找到参数的偏移，结果为10，实际上为%9$n。

![offset](./2.jpg)

下面需要想办法泄露出存储返回地址的栈地址，依然是在刚才的断点处，stack 50看下此时的栈上情况，可以看到libc_start_main+241那里就是返回地址，可以是0xffc971cc也可以是0xffc971dc，这里选择后者，这个栈地址要泄露出来，需要栈上另一个存储了相关地址，根据这个地址计算出来即可（因为没有ASLR所以地址固定）。在偏移为84的地方有一个栈地址存储的内容和返回地址栈地址之间的差为4，即泄露的地址减4即为栈地址。继续使用fmtarg 得到字符串的偏移为22，这个偏移是相对于函数来说，因此相对于字符串参数的偏移为21，使用%21$p打印出这个栈地址，减去4得到返回地址所在的栈地址，再覆盖这个地址里的内容跳转到目标函数

![return_addr](./3.jpg)

![leak_offset](./4.jpg)

##
exp.py
之前写的exp今天执行报错，所以换了官方的wp代码。尴尬地是代码也挂了，payload都是一样的，可能是网络连通的问题

![exp](./5.jpg)

![flag](./6.jpg)
