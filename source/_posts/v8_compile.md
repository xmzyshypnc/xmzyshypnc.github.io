---
title: v8编译踩坑记
categories:
- v8
---

# v8编译踩坑记

## 前言

打算看姚老板的博客学下oob，试图编译v8，结果踩了一堆坑，linux遇到问题之后求助P1umer，改成了win，win那边也是问题连连，决定还是改回linux，下面就记录一下v8编译的一些问题及解决方法

## 设置代理

我宿主机用的是SSR，代理端口为1080，虚拟机设置NAT，SSR允许局域网代理，在宿主机查看一下本机ip`192.168.*.*`，两边互ping一下即可。

git的代理可以直接设置socks5代理，命令如下`git config --global http.proxy "socks5://192.168.*.*:1080"`，不过socks5代理后面会出问题，这里可以先用socks5

终端代理可以设置export临时用，也可以在~/.bashrc中添加export再source长久使用，命令位`export http_proxy="socks5://192.168.*.*:1080"`以及`export https_proxy=$http_proxy`或者`export ALL_PROXY="socks5://192.168.*.*:1080"`一条同时设置http和https。

## 安装depot_tools

从github中下载repo即可，之后添加环境变量到终端配置文件中

```bash
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
echo 'export PATH=$PATH:"/path/to/depot_tools"' >> ~/.bashrc
```

## 安装ninja

从github下repo，同样要添加环境变量

```bash
git clone https://github.com/ninja-build/ninja.git
cd ninja && ./configure.py --bootstrap && cd ..
echo 'export PATH=$PATH:"/path/to/ninja"' >> ~/.bashrc
```

## 编译v8

`gclient`初始化工具集失败，提示有`Bootstrapping cipd client`，报错原因`curl: (35) gnutls_handshake() failed: The TLS connection was non-properly terminated`，具体原因是curl不能通过代理成功连接到主机，根本原因是proxychains使用socks5协议，但是cipd不支持，下面有两个解决方案，一是手动安装cipd，另一个是将socks5协议转http协议，我参考的是[这篇文章](https://www.cnblogs.com/hcbin/p/8630143.html)

## socks5转http

下载polipo

```bash
git clone https://github.com/jech/polipo.git
```

安装
```bash
cd polipo
sudo make all
sudo make install
```

新建文件
```bash
sudo vim /etc/polipo.conf
```

添加以下内容(我这里将宿主机的socks5转到了虚拟机的localhost:8090)

```conf
daemonise = false
pidFile = /tmp/polipo.pid
proxyAddress="0.0.0.0"
proxyPort=8090
socksParentProxy = "192.168.86.1:1080"
socksProxyType = socks5
diskCacheRoot = ""
```

换个终端执行polipo

```bash
/usr/local/bin/polipo -c /etc/polipo.conf
```

## 设置depot_tools代理

不设置的话download_from_google_storage会提示NO_AUTH_BOTO_CONFIG

新建文件

```bash
vim /etc/gclient_boto.cfg
```

添加如下内容

```conf
[Boto]
proxy = 127.0.0.1
proxy_port = 8090
```

终端设置变量

```bash
export NO_AUTH_BOTO_CONFIG=/etc/gclient_boto.cfg
```

## 设置git

```bash
git config --global core.packedgitlimit 10g
git config --global core.packedgitwindowsize 10g
git config --global core.bigfilethreshold 10g
git config --global core.compression 0
git config --global core.autocrlf false
git config --global core.filemode false
git config --global pack.deltacachesize 10g
git config --global pack.packsizelimit 10g
git config --global pack.windowmemory 10g
git config --global pack.threads 4
```

## 下载源码 && 编译

```bash
mkdir v8
cd v8 
fetch v8
tools/dev/v8gen.py x64.debug
ninja -C out.gn/x64.debug
```
编译的二进制文件为d8，位于`./out.gn/x64.debug/d8`

## 参考文章

[P1umer](https://p1umer.github.io/2018/07/01/V8-Environmental-Configuration/)

[HCBin](https://www.cnblogs.com/hcbin/p/8630143.html)

[holing](https://mem2019.github.io/jekyll/update/2019/07/18/V8-Env-Config.html)
