**SearchMap_V1.0.2** 

**searchmap是一款集域名解析、IP反查域名、WHOIS查询、CDN检测、端口扫描、目录扫描、子域名挖掘为一体的前渗透测试综合信息收集工具。**
![image](https://user-images.githubusercontent.com/67818638/133013451-1d3f8310-6c17-4985-b526-9d9af9e8302c.png)
**一.安装说明**

1.工具使用python3开发，请确保您的电脑上已经安装了python3环境。

2.工具的端口扫描功能调用了nmap接口，请确保您的电脑已安装nmap。

3.首次使用请使用 **python3 -m pip install -r requirements.txt** 命令，来安装必要的外部依赖包。

4.本机未安装pip工具的请使用如下命令来进行安装：

```
$ curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py   # 下载安装脚本
$ sudo python get-pip.py    # 运行安装脚本。
注意：用哪个版本的 Python 运行安装脚本，pip 就被关联到哪个版本，如果是 Python3 则执行以下命令：
$ sudo python3 get-pip.py    # 运行安装脚本。
一般情况 pip 对应的是 Python 2.7，pip3 对应的是 Python 3.x。
部分 Linux 发行版可直接用包管理器安装 pip，如 Debian 和 Ubuntu：
sudo apt-get install python-pip
```

**二.使用方法**

**1.-u 获取网站基本信息**

```
$ python3 searchmap.py -u  https://www.baidu.com
$ python3 searchmap.py -u  106.53.143.192
```
<img width="1439" alt="image" src="https://user-images.githubusercontent.com/67818638/132992898-48d91ffb-2cc4-4da6-9a4d-ac00cb998548.png">

![image-20211123223951575](/Users/qiuan/Library/Application Support/typora-user-images/image-20211123223951575.png)


**2.-p 使用nmap进行隐式端口扫描**

```
$ python3 searchmap.py -u  https://www.baidu.com -p
```
<img width="1439" alt="image" src="https://user-images.githubusercontent.com/67818638/132992984-3ac8b0c0-1093-43ea-b5a3-666b27514b04.png">

**3.-r 批量扫描网站基本信息**

```
$ python3 searchmap.py -r myurl.txt  
```
<img width="1439" alt="image" src="https://user-images.githubusercontent.com/67818638/132993016-c8dd3755-ba5f-4c45-913a-e87e9354131a.png">

**4.-n 使用多地ping来判断目标是否使用cdn加速**

```
$ python3 searchmap.py -u  https://www.baidu.com -n
```
<img width="1438" alt="image" src="https://user-images.githubusercontent.com/67818638/132993047-6bb10167-6c04-42bf-b5a9-a6d40068bd8b.png">

**5.-d 对网站目录进行多进程扫描探测，能够自动识别伪响应页面**

PS:程序使用的默认字典为dict/fuzz.txt，用户可自行替换字典内容进行FUZZ。

```
$ python3 searchmap.py -u  https://www.baidu.com  -d
```
<img width="1420" alt="image" src="https://user-images.githubusercontent.com/67818638/132993085-a79eaf65-550a-4d07-89bb-4d5bdd75279a.png">

**6.-s 对输入域名的进行子域名爆破**

PS:程序使用的默认字典为dict/subdomain.txt，用户可自行替换字典内容进行FUZZ。

```
$ python3 searchmap.py -u  https://www.baidu.com  -s
```
<img width="1438" alt="image" src="https://user-images.githubusercontent.com/67818638/132993137-f0a52d2b-2c8c-441f-8433-b63c84aeefa4.png">

**7.-a 对目标域名进行全功能扫描**

```
$ python3 searchmap.py -u  https://www.baidu.com  -a
```

**8.-o 将扫描内容保存为日志**

```
$ python3 searchmap.py -u  https://www.baidu.com  -o myscan.log
```

**9.组合用法**

```
$ python3 searchmap.py -u  https://www.baidu.com -p -n -d -s

$ python3 searchmap.py -r  myurl.txt -p -n -d -s
```



*PS：安全小白一枚，第一次写工具有很多BUG，欢迎大家提交Issues.*

****************************

**本工具仅提供给安全测试人员进行安全自查使用**
**用户滥用造成的一切后果与作者无关**
**使用者请务必遵守当地法律**
**本程序不得用于商业用途，仅限学习交流**

*********

**Version1.0.2_UpdateLog**
-------------------------------------
1.优化工具对IP地址的支持

2.新增IP地址反查域名功能

*********

**Version1.0.1_UpdateLog**
-------------------------------------

1.新增加日志功能，可以自定义是否输出系统日志
