**SearchMap_V1.2.0**

searchmap是一款集**域名解析、DNS记录枚举、WHOIS查询、CDN检测、纯Python智能端口扫描、TLS证书识别、HTTP/服务指纹、智能目录扫描、子域名挖掘、结构化导出**为一体的前渗透测试综合信息收集工具。新版本继续强化**稳定性、性能和结果可靠性**，移除了对 `nmap`、IP归属地API、反查网页等外部工具/第三方数据接口的依赖，核心侦察能力尽量由本地Python网络能力完成，适合授权安全自查和资产梳理。
![image](https://user-images.githubusercontent.com/67818638/133013451-1d3f8310-6c17-4985-b526-9d9af9e8302c.png)

## 一.功能特性

- **域名/IP基础信息**: 快速解析域名，获取IPv4/IPv6地址、PTR记录和公网/内网/保留地址分类。
- **DNS记录枚举**: 自动收集A、AAAA、CNAME、NS、MX、TXT、SOA、CAA等关键记录。
- **WHOIS查询**: 获取域名的详细注册信息。
- **多解析器DNS检测 (CDN识别)**: 并行查询多个公共DNS解析器，通过IP差异和CDN CNAME特征判断目标是否使用CDN或负载均衡。
- **HTTP/TLS/服务指纹**: 自动识别网站标题、Server、X-Powered-By、常见技术栈、安全响应头、favicon hash、robots/sitemap/security.txt，以及TLS版本、证书主体、颁发者、有效期和SHA256指纹。
- **纯Python智能端口扫描**: 使用TCP connect扫描和Banner探测替代Nmap，内置`fast`、`smart`、`common/top1000`、`web`、`full`等端口集，并对开放端口进行服务/Web/TLS指纹识别。
- **智能目录与子域名爆破**: 目录扫描使用连接池和限量读取提升速度，支持路径扩展、`%EXT%`扩展、robots/sitemap种子、软404基线过滤、敏感路径标签、递归扫描；子域名扫描内置泛解析过滤。
- **批量处理**: 支持从文件读取多个目标进行批量扫描。
- **日志与结构化输出**: 支持控制台日志、JSON结果和CSV发现项导出，方便归档和二次分析。
  
## 二.安装说明

1.工具使用python3开发，请确保您的电脑上已经安装了python3环境。

2.首次使用请使用 **python3 -m pip install -r requirements.txt** 命令，来安装必要的Python依赖包。端口扫描不再依赖nmap等外部二进制工具。

3.本机未安装pip工具的请使用如下命令来进行安装：

```
$ curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py   # 下载安装脚本
$ sudo python get-pip.py    # 运行安装脚本。
注意：用哪个版本的 Python 运行安装脚本，pip 就被关联到哪个版本，如果是 Python3 则执行以下命令：
$ sudo python3 get-pip.py    # 运行安装脚本。
一般情况 pip 对应的是 Python 2.7，pip3 对应的是 Python 3.x。
部分 Linux 发行版可直接用包管理器安装 pip，如 Debian 和 Ubuntu：
sudo apt-get install python-pip
```

## 三.使用方法

> 说明：V1.2.0 输出内容会随目标、网络环境和解析器返回结果变化，旧版本终端截图已移除。以下示例以命令为准。

**1.-u 获取基础信息、DNS记录、HTTP/TLS指纹**

```
$ python3 searchmap.py -u https://www.baidu.com
```

```
$ python3 searchmap.py -u 123.123.123.123
```

**2.-p 使用纯Python TCP connect进行端口扫描**

```
$ python3 searchmap.py -u https://www.baidu.com -p
```

默认使用`smart`端口集，并对开放端口进行服务名、Banner、HTTP和TLS指纹探测，最后会输出指纹汇总。

**3.--ports 自定义端口集合**

```
# 支持 fast/top100、smart、common/top1000、web、full、单端口、逗号列表和端口范围
$ python3 searchmap.py -u https://www.baidu.com -p --ports web
$ python3 searchmap.py -u https://www.baidu.com -p --ports common
$ python3 searchmap.py -u https://www.baidu.com -p --ports 80,443,8000-8100
```

**4.-n 使用多解析器DNS检测CDN/负载均衡**

```
$ python3 searchmap.py -u https://www.baidu.com -n
```

也可以指定自定义解析器：

```
$ python3 searchmap.py -u https://www.baidu.com -n --resolver 8.8.8.8 --resolver 1.1.1.1
```

**5.-d 对网站目录进行多线程扫描探测，能够自动识别伪响应页面**

PS: 程序使用的默认字典为`dict/fuzz.txt`，用户可自行替换字典内容进行FUZZ。

```
$ python3 searchmap.py -u https://www.baidu.com -d
$ python3 searchmap.py -u https://www.baidu.com -d --dict dict/fuzz.txt
```

智能目录扫描参数：

```
# fast更快，smart默认更均衡，deep会增加备份文件变体和递归扫描
$ python3 searchmap.py -u https://www.baidu.com -d --dir-mode fast
$ python3 searchmap.py -u https://www.baidu.com -d --dir-mode deep --dir-depth 1

# 自定义%EXT%扩展、关注状态码和单响应最大读取字节
$ python3 searchmap.py -u https://www.baidu.com -d --dir-ext php,asp,aspx,jsp,html,js --dir-status 200,301,302,401,403 --max-body 32768
```

**6.-s 对输入域名的进行子域名爆破**

PS: 程序使用的默认字典为`dict/subdomain.txt`，用户可自行替换字典内容进行FUZZ。

```
$ python3 searchmap.py -u https://www.baidu.com -s
$ python3 searchmap.py -u https://www.baidu.com -s --subdict dict/subdomain.txt
```

**7.-a 对目标域名进行全功能扫描**

```
$ python3 searchmap.py -u https://www.baidu.com -a
```

**8.-r 批量扫描目标**

```
$ python3 searchmap.py -r myurl.txt
$ python3 searchmap.py -r myurl.txt -p -n -d -s
```

**9.-o 将控制台扫描内容保存为日志**

```
$ python3 searchmap.py -u https://www.baidu.com -o myscan.log
```

**10.--json-out / --csv-out 导出结构化结果**

```
$ python3 searchmap.py -u https://www.baidu.com -a --json-out result.json --csv-out findings.csv
$ python3 searchmap.py -r myurl.txt -p -n --json-out batch-result.json --csv-out batch-findings.csv
```

**11.-t / --timeout 控制并发和超时**

```
# 使用50个线程进行全方位扫描，并将单次网络超时设为3秒
$ python3 searchmap.py -u https://www.baidu.com -a -t 50 --timeout 3
```

**12.组合用法**

```
$ python3 searchmap.py -u https://www.baidu.com -p -n -d -s --ports smart
$ python3 searchmap.py -r myurl.txt -a -t 50 --timeout 3 --dir-all-web --json-out result.json
```



*PS：安全小白一枚，第一次写工具有很多BUG，欢迎大家提交Issues.*

****************************

**本工具仅提供给安全测试人员进行安全自查使用**
**用户滥用造成的一切后果与作者无关**
**使用者请务必遵守当地法律**
**本程序不得用于商业用途，仅限学习交流**

*********

**【打赏支持❤️】代码传情跨山海，点滴支持皆温暖✨**

虽然代码完全开源，但每杯咖啡都能让我们走得更远 ☕️

<img width="500" height="400" alt="打赏码" src="https://github.com/user-attachments/assets/02868aed-357e-4740-983a-d5a8ea05bdbf" />

**【战队公众号】扫描关注战队公众号，获取最新动态**

<img width="318" alt="image" src="https://user-images.githubusercontent.com/67818638/149507366-4ada14db-a972-4071-bbb6-197659f61ced.png">

**【知识星球福利】福利大放送，扫码加入知识星球**

<img width="318" alt="image" src="https://github.com/asaotomo/ZipCracker/assets/67818638/659b508c-12ad-47a9-8df5-f2c36403c02b">

## 四.更新日志

*********
**Version1.2.0_UpdateLog**
-------------------------------------
1. **端口扫描增强**: 默认端口集升级为`smart`，新增`fast/top100`、`common/top1000`、`web`、`full`预设，保留端口列表和范围写法。
2. **开放端口指纹**: 对开放端口自动进行Banner、HTTP、TLS、Server、Title、技术栈和favicon hash探测，并以表格展示。
3. **目录扫描提速**: 使用线程内连接池、HTTP keep-alive和响应体限量读取，降低大页面下载造成的拖慢。
4. **目录扫描智能化**: 新增`--dir-mode fast|smart|deep`、`--dir-ext`、`--dir-status`、`--dir-depth`、`--dir-all-web`、`--max-body`参数。
5. **目录发现增强**: 支持`%EXT%`自动扩展、目录斜杠变体、内置敏感路径、robots.txt和sitemap.xml种子路径。
6. **误报过滤增强**: 优化软404判断，降低真实页面被长度相近误杀的概率。
7. **敏感路径标签**: 对`.git`、`.env`、备份文件、数据库备份、Swagger/OpenAPI、GraphQL、后台登录、运维端点等结果自动打标签。
8. **最终指纹汇总**: 扫描结束统一输出开放端口、Web目标、技术栈和高价值目录发现，并写入JSON/CSV结果。

*********
**Version1.1.0_UpdateLog**
-------------------------------------
1. **外部工具依赖移除**: 端口扫描由Nmap改为纯Python TCP connect扫描，并加入Banner/TLS探测。
2. **第三方数据API依赖移除**: 删除ipinfo.io归属地查询和ip138网页反查，改为本地可完成的IP分类、PTR、DNS、WHOIS、HTTP/TLS信息收集。
3. **新增HTTP/TLS指纹**: 自动采集网站标题、响应头、技术栈、安全响应头、robots/sitemap/security.txt和TLS证书信息。
4. **新增DNS记录枚举**: 支持A、AAAA、CNAME、NS、MX、TXT、SOA、CAA记录收集。
5. **端口扫描增强**: 新增`--ports`参数，支持`top100`、`web`、端口列表和范围。
6. **目录扫描增强**: 加入随机基线软404过滤，降低误报。
7. **子域名扫描增强**: 加入泛解析识别和过滤。
8. **结构化输出**: 新增`--json-out`和`--csv-out`，便于归档、比对和后续分析。
9. **健壮性优化**: 重写目标解析、IPv6 URL处理、线程数限制、超时控制和错误收集。

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
