# OpenWrt-Based-Router-Traffic-Monitoring
## 概述

- 基于OpenWRT的网络路由流量监测系统，可以统计：

    a. 源IP地址/⽬的IP地址

    b. 累计接收(发送)流量

    c. 流量峰值

    d. 过去某个时间段的平均流量，例如：过去2s、过去10s、过去40s.

- 路由器型号:H3C Magic Nx30 Pro 

- 运行效果：

  <img src="README.assets/屏幕截图 2025-06-23 235323.png" style="zoom: 50%;" />

------

## 文件目录

Demo Packages：源代码、编译包以及编译后可安装程序包。

Guidebook：开发过程中的实验指导书。

StageⅠ/Ⅱ：开发过程中的PDF版记录，阶段代码。

------



## 如何使用

### 该型号路由器

1. 在[官⽹](https://firmware-selector.openwrt.org/)下搜索设备对应的固件，下载后刷入对应型号路由器，实现Opemwrt刷入；
2. 在主机终端使用SSH登录Openwrt系统；
3. 使用Winscp（或者其他方式）传输程序“traffic_monitor”至/tmp/(或者其他目录)；
4. 安装对应依赖包，执行程序：

```shell
#安装libpcap
opkg update
opkg install libpcap
# 将程序放在 /usr/sbin/ 
mv /tmp/traffic_monitor /usr/sbin/
#给予权限并运⾏
chmod +x /usr/sbin/traffic_monitor
/usr/sbin/traffic_monitor
```



### 其他型号路由器

参考[我的博客](https://www.kiwitcheng.top/article/21bc5dcc-def5-80e3-9d28-eb1cf15d43bf) ，或者：Stage Ⅱ/基于OpenWrt的网络路由器流量监测-交叉编译与路由器配置 .pdf，或者：Guidebook/，交叉编译后上传运行（与上一节类似）

------

## 相关博客

[跳转点击](https://www.kiwitcheng.top/category/%E7%BD%91%E7%BB%9C%E5%BC%80%E5%8F%91)

------



## Todo

- [ ]   a. 开发前端可视化界面与后端服务器接⼝，通过发送 HTTP 请求获取流量监控的实时数据信息，并将其直观呈现于前端界面，以实现数据的实时监测与可视化展示。

- [x]   b. 烧制openwrt操作系统，在真实的路由器环境中部署流量监控程序。
- [ ]   c.使用USB外部存储设备，挂载拓展功能后的可执行程序。

