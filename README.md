**SearchMap_V1.0.0** 

**searchmap是一款集域名解析、WHOIS查询、CDN检测、端口扫描、目录扫描、子域名挖掘为一体的前渗透测试综合信息收集工具。**

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
```

**2.-p 使用nmap进行隐式端口扫描**

```
$ python3 searchmap.py -u  https://www.baidu.com -p
```

**3.-r 批量扫描网站基本信息**

```
$ python3 searchmap.py -r myurl.txt  
```

**4.-n 使用超级ping来判断目标是否使用cdn加速**

```
$ python3 searchmap.py -u  https://www.baidu.com -n
```

**5.-d 对网站目录进行多进程扫描探测，能够自动识别伪响应页面 **

PS:程序使用的默认字典为dict/fuzz.txt，用户可自行替换字典内容进行FUZZ。

```
$ python3 searchmap.py -u  https://www.baidu.com  -d
```

**6.-s 对输入域名的进行子域名爆破 **

PS:程序使用的默认字典为dict/subdomain.txt，用户可自行替换字典内容进行FUZZ。

```
$ python3 searchmap.py -u  https://www.baidu.com  -s
```

**6.-a 对目标域名进行全功能扫描 **

```
$ python3 searchmap.py -u  https://www.baidu.com  -a
```

**7.组合用法**

```
$ python3 searchmap.py -u  https://www.baidu.com -p -n -d -s

$ python3 searchmap.py -r  myurl.txt -p -n -d -s
```



*PS：安全小白一枚，第一次写工具有很多BUG，欢迎大家提交Issues*

****************************

**本工具仅提供给安全测试人员进行安全自查使用**
**用户滥用造成的一切后果与作者无关**
**使用者请务必遵守当地法律**
**本程序不得用于商业用途，仅限学习交流**

*********
