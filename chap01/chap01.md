# 网络安全第一章实验报告  
## 基于VirtualBox的网络攻防基础环境搭建  
### 实验目的  
* 掌握VirtualBox虚拟机的安装与使用  
* 掌握VirtualBox的虚拟网络类型和按需配置  
* 掌握VirtualBox的虚拟硬盘多重加载  

### 实验环境  
以下是本次实验需要使用的网络节点说明和主要软件举例：  

* VirtualBox虚拟机  
* 攻击者主机(Attacker):Kali Rolling  
* 网关(Gateway):Debian Buster  
* 靶机(Victim):xp-sp3/Kali  

### 实验过程  

#### 虚拟机安装  
* 下载系统对应镜像文件  
 * Kali: kali-linux-2020.3-installer-amd64.iso  
 * Debian: debian-10.5.0-amd64-netinst.iso  
 * xp-sp3: zh-hans_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-74070.iso  
* 分别进行首次安装系统  
 * [Debian安装参照文档](https://phoenixnap.com/kb/how-to-install-debian-10-buster)  
 * xp序列号 dg8fv-b9tky-frt9j-6crcc-xpq4g  
* 配置多重加载  
 * 管理-虚拟介质管理  
  ![1](./image/1.jpg)  
 * 属性-类型-多重加载-应用  
  ![2](./image/2.jpg)  
 * 新建虚拟机时选择使用已有的虚拟硬盘文件  
  ![3](./image/3.jpg)  

#### 网络环境配置  
* 配置目标  
![4](./image/4.png)  
* 实际对应关系  
Attacker——KALI-att  
Gateway——DEBIAN-1  
Internal1——KKK/XPprofessional  
Internal2——DEBIAN-2/XP2  
![5](./image/5.jpg)
* 配置过程  
 1. 配置虚拟机Host-Only网卡  
 管理-主机网络管理  
![6](./image/6.jpg)  
 2. 配置网关网卡  
![7](./image/7.jpg)  
发现网卡2、3、4均没有获得IP地址  
更改`/etc/network/interfaces`配置 [更改参考](https://gist.github.com/c4pr1c3/8d1a4550aa550fabcbfb33fad9718db1)  
`systemctl restart networking`重启网络服务  
![8](./image/8.jpg)
 3. 网关安装dnsmasq服务器  
`apt update && apt install dnsmasq`下载安装  
更改`/etc/dnsmasq.conf`配置 [更改参考](https://gist.github.com/c4pr1c3/8d1a4550aa550fabcbfb33fad9718db1)  
`systemctl restart dnsmasq`重新启动  
![29](./image/29.jpg)
 4. 配置靶机  
intnet1:
     * XPprofessional:  
![9](./image/9.jpg)  
![10](./image/10.jpg)  
     * KKK:  
![11](./image/11.jpg)  
![12](./image/12.jpg)  
intnet2:  
     * XP2:  
![13](./image/13.jpg)  
![14](./image/14.jpg)  
     * DEBIAN-2:  
![15](./image/15.jpg)  
![16](./image/16.jpg)  

### 网络连通性检验  
 - [x] 靶机可以直接访问攻击者主机  
 攻击者IP地址:  
![17](./image/17.jpg)  
intnet1-XPprofessional:  
![18](./image/18.jpg)  
intnet2-DEBIAN-2:  
![19](./image/19.jpg)
 - [x] 攻击者主机无法直接访问靶机  
 ![20](./image/20.jpg)
 - [x] 网关可以直接访问攻击者主机和靶机  
 访问靶机：
 ![21](./image/21.jpg)  
访问攻击者主机：  
![22](./image/22.jpg)
 - [x] 靶机的所有对外上下行流量必须经过网关  
 网关：  
`apt update && apt install tmux`安装tmux  
`apt install tcpdump`安装tcpdump  
`tcpdump -i enp0s10 -n -w 20200921.1.pcap`  
![30](./image/30.jpg)  
 - [x] 所有节点均可以访问互联网  
网关：  
![23](./image/23.jpg)  
攻击者主机：  
![24](./image/24.jpg)  
靶机：  
![25](./image/25.jpg)  
![26](./image/26.jpg)  
![27](./image/27.jpg)  
![28](./image/28.jpg)  

### tips:  
1. 网卡切换NAT网络时显示无效设置  
管理-全局设定-网络-添加新NAT网络  
![31](./image/31.jpg)  
2. XP系统网卡  
选择千兆网卡可以继续完成后续所有实验  
![32](./image/32.jpg)




