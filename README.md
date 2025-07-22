**SearchMap_V1.0.3** 

searchmap是一款集**域名解析、IP反查域名、WHOIS查询、CDN检测、端口扫描、目录扫描、子域名挖掘**为一体的前渗透测试综合信息收集工具。新版本在原版基础上进行了**全面重构**，专注于提升**稳定性、性能和结果的可靠性**。它用更健壮的API和并发模型取代了原先脆弱的网页抓取逻辑，并增加了更丰富的信息展示，旨在成为您侦察阶段的得力助手。
![image](https://user-images.githubusercontent.com/67818638/133013451-1d3f8310-6c17-4985-b526-9d9af9e8302c.png)

## 一.功能特性

- **域名/IP基础信息**: 快速解析域名，获取IP地址列表，并自动查询所有IP的地理位置。
- **WHOIS查询**: 获取域名的详细注册信息。
- **多节点DNS检测 (CDN识别)**: 通过并行查询全球多个地区的公共DNS服务器，高效、稳定地判断目标是否使用CDN或负载均衡。
- **IP归属地查询**: 所有展示IP地址的地方（基础信息、DNS检测）都会自动附带其物理归属地，信息更直观。
- **Nmap端口扫描**: 集成Nmap，可对目标IP进行快速的端口和服务扫描。
- **多线程目录与子域名爆破**: 高效的并发引擎，快速对目标进行目录和子域名探测。
- **批量处理**: 支持从文件读取多个目标进行批量扫描。
- **日志记录**: 可将所有扫描结果输出到日志文件，方便归档和分析。
  
## 二.安装说明

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
<img width="1354" height="488" alt="image" src="https://github.com/user-attachments/assets/aaf380f3-a44a-493a-8396-4f19a0ec60e6" />


```
$ python3 searchmap.py -u  123.123.123.123
```
<img width="877" height="854" alt="image" src="https://github.com/user-attachments/assets/c396b4f1-11be-4fde-9270-657e3438b351" />


**2.-p 使用nmap进行隐式端口扫描**

```
$ python3 searchmap.py -u  https://www.baidu.com -p
```
<img width="989" height="635" alt="image" src="https://github.com/user-attachments/assets/8e3ddaa7-28f2-4294-afed-187a990ec7f4" />


**3.-r 批量扫描网站基本信息**

```
$ python3 searchmap.py -r myurl.txt  
```
<img width="1353" height="878" alt="image" src="https://github.com/user-attachments/assets/900aa197-6822-41ec-b293-af723dab34b6" />


**4.-n 使用多节点DNS检测来判断目标是否使用cdn加速**

```
$ python3 searchmap.py -u  https://www.baidu.com -n
```
<img width="1823" height="701" alt="image" src="https://github.com/user-attachments/assets/698ba233-68a1-46d2-b79e-6666140f9172" />

**5.-d 对网站目录进行多线程扫描探测，能够自动识别伪响应页面**

PS:程序使用的默认字典为dict/fuzz.txt，用户可自行替换字典内容进行FUZZ。

```
$ python3 searchmap.py -u  https://www.baidu.com  -d
```
<img width="976" height="687" alt="image" src="https://github.com/user-attachments/assets/a2a4e52b-1421-40a3-8281-eb1e6fe12f45" />


**6.-s 对输入域名的进行子域名爆破**

PS:程序使用的默认字典为dict/subdomain.txt，用户可自行替换字典内容进行FUZZ。

```
$ python3 searchmap.py -u  https://www.baidu.com  -s
```
<img width="1028" height="859" alt="image" src="https://github.com/user-attachments/assets/bf8e9776-f857-4308-9161-c00ddb08ad4a" />

**7.-a 对目标域名进行全功能扫描**

```
$ python3 searchmap.py -u  https://www.baidu.com  -a
```

**8.-o 将扫描内容保存为日志**

```
$ python3 searchmap.py -u  https://www.baidu.com  -o myscan.log
```

**9.-t 自定义扫描线程数**

```
# 使用50个线程进行全方位扫描，速度更快
$ python3 searchmap.py -u https://www.baidu.com -a -t 50
```

**10.组合用法**

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

**扫码加入知识星球**

<img width="318" alt="image" src="https://user-images.githubusercontent.com/67818638/147641794-82f32969-4214-48da-9df2-764318225589.png">

**扫描关注战队公众号，获取最新动态**

<img width="318" alt="image" src="https://user-images.githubusercontent.com/67818638/149507366-4ada14db-a972-4071-bbb6-197659f61ced.png">

**【知识星球】福利大放送**

<img width="318" alt="image" src="https://github.com/asaotomo/ZipCracker/assets/67818638/659b508c-12ad-47a9-8df5-f2c36403c02b">


*********
**Version1.0.3_UpdateLog**
-------------------------------------
1. **核心重构**: 升级并发模型，使用线程池（ThreadPoolExecutor）替代多进程，显著提升I/O性能和稳定性。
2. **功能升级-CDN检测**: 重写多地Ping（-n）功能，采用查询全球公共DNS的稳定方式，彻底解决了原先依赖网页抓取而导致功能失效的问题。
3. **功能升级-IP归属地**: 升级IP归属地查询功能，使用稳定的`ipinfo.io` API，解决了原接口失效的问题，并为所有输出的IP地址（包括基础信息和多地DNS检测）增加了归属地显示。
4. **BUG修复**: 修复了当URL中包含端口号时，导致域名解析失败的严重Bug。
5. **BUG修复**: 修复了当字典文件（子域名、目录）中存在空行时，导致程序崩溃的Bug。
6. **新增参数**: 新增`-t/--threads`参数，允许用户根据自身网络情况自定义并发线程数。
7. **代码健壮性**: 整体代码迁移到面向对象的类结构中，消除了全局变量，并优化了多处错误处理逻辑。

*********
**Version1.0.2_UpdateLog**
-------------------------------------
1.优化工具对IP地址的支持

2.新增IP地址反查域名功能

3.修复cms检测Bug

4.修复whois查询报错问题

*********

**Version1.0.1_UpdateLog**
-------------------------------------

1.新增加日志功能，可以自定义是否输出系统日志
