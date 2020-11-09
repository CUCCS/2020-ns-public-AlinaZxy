# 网络安全第七章实验报告  
## Web 应用漏洞攻防 - WebGoat  

### 实验目的  
* 了解常见 Web 漏洞训练平台  
* 了解常见 Web 漏洞的基本原理  
* 掌握 OWASP Top 10 及常见 Web 高危漏洞的漏洞检测、漏洞利用和漏洞修复方法  

### 实验环境  
* Kali  
* WebGoat 7.0.1  
* Burp Suite v2020.9.2  
* Chrome  

### 实验要求  
 - [x] 每个实验环境完成不少于5种不同漏洞类型的漏洞利用练习  
 - [x] （可选）使用不同于官方教程中的漏洞利用方法完成目标漏洞利用练习  
 - [ ] （可选）最大化漏洞利用效果实验  
 - [x] （可选）编写自动化漏洞利用脚本完成指定的训练项目  
 - [x] （可选）定位缺陷代码  
 - [ ] （可选）尝试从源代码层面修复漏洞  

### 实验过程  

#### WebGoat  
* 实验环境准备  
    ```
    #安装docker-compose  
    sudo apt update && sudo apt install docker-compose  
    #查看docker镜像  
    apt policy docker.io  
    ```  
    ![查看docker](./image/查看docker版本.png)  
    ```
    #配置环境  
    cd owasp/webgoat/ && sudo docker-compose up -d  
    ```  
    ![配置环境](./image/配置环境.png)  
    ```
    #检测容器当前状态  
    docker ps  
    ```  
    ![healthy证明](./image/healthy证明.png)  
*  更改配置 在主机中直接访问（别问 问就是虚拟机浏览器卡到怀疑人生
    更改`docker-compose.yml`  
    ![dockercompose](./image/dockercomposeyml.png)  
    在主机中访问host-only网卡IP地址及开放端口号  
    ![webgoat7](./image/webgoat7.png)  
    ![webgoat8](./image/webgoat8.png)  

##### WebGoat 7.1  
* General  
    * Http Basics  
    按照题目提示，完成一次Burp Suite操作即成功  
    ![Http Basics](./image/httpbas.png)  

* Authentication Flaws  
    * Forgot Password  
    题目提示输入用户名，尝试几次，admin成功，密码提示最喜欢的颜色，例举几个颜色，green成功  
    ![Forgot Password](./image/forgotpass.png)  
    * Password Strength  
    提交不同强度密码所对应的测试时间(参考答案时间)  
    ![Password Strength](./image/passstr.png)  
    实际在[www.security.org](https://www.security.org/how-secure-is-my-password/)测试结果：  

        |Password|time|
        | ---- | ---- |
        |123456|Instantly|
        |abzfezd|0.2 seconds|
        |a9z1ezd|1 seconds|
        |aB8fEzDq|1 hours|
        |z8!E?7D$|2 days|
        |My1stPassword!:Redd|36 quintillion years|  
    * Multi Level Login 2  
    第一次输入给定用户密码登录后再输入tan后发现此时只对应`username`和`tan`，修改对应`hidden_user`  
    ![Multi Level Login 2](./image/Multi2.png)  
    注：可能尝试次数过多，突然出现了`TAN #0`的bug(暂时无解  
    ![TAN 0](./image/tan0.png)  
    * Multi Level Login 1  
    任务一按照提示输入用户名密码及Tan完成登录  
    ![Multi Level Login 1 S1](./image/Multi1t1.png)  
    任务二由于仅知道`Tan #1`的值，所以将`hidden_tan`改为1  
    ![Multi Level Login 1 S2](./image/Multi1t2.png)  
    ![Multi Level Login 1](./image/Multi1.png)  

* AJAX Security  
    * DOM Injection  
    根据页面提示，检查源代码，果然在Activate处发现端倪  
    ![DOM Injection](./image/dominj.png)  
    删除`disabled`重新提交，完成实验  
    ![DOM Injection result](./image/domres.png)  
    * LAB: DOM-Based cross-site scripting  
    虽然CTF曾经听过一节XSS，奈何实在太菜，此题除第一问外，其他均参考题解  
    ![LAB: DOM-Based cross-site scripting Stage1](./image/LABdoms1.png)  


* Injection Flaws  
    * String SQL Injection  
    碰巧刚刚听过一节CTF关于SQL注入的课，用师姐讲的办法尝试了一下  
    ![String SQL Injection](./image/StringSQL.png)  
    * Numeric SQL Injection  
    简单数字型SQL注入  
    ![Numeric SQL Injection](./image/numericsql.png)  
    * Command Injection  
    Burp Suite拦截HTTP请求，更改`HelpFile`值添加`"&&cat "/etc/passwd`实现注入  
    ![commandinj](./image/commandinj.png)  
    ![Command Injection](./image/commandinjection.png)  
    注：参考[2020-ns-public-chococolate](https://github.com/CUCCS/2020-ns-public-chococolate/blob/chap0x07-webgoat/chap0x07-webgoat/chap0x07-webgoat.md)  
    * Log Spoofing  
    利用输入数据完成日志欺骗  
    ![Log Spoofing](./image/logspoof.png)  
    注：参考提示  
    * XPATH Injection  
    不仅仅考虑SQL注入，同时还要关注XPATH的过滤规则  
    ![XPATH Injection](./image/xpath.png)  


* Parameter Tampering  
    * Exploit Hidden Fields  
    对于某次CTF比赛讲解视频有一点点印象，尝试利用Burp Suite修改总价为0，成功  
    ![Exploit Hidden Fields](./image/exploit.png)  

* Code Quality  
    * Discover Clues in the HTML  
    根据标题，在HTML中发现线索，尝试在源代码中寻找线索，果然发现用户名及密码  
    ![Discover Clues in the HTML](./image/disclue.png)  
    ![Discover Clues in the HTML result](./image/disclueresult.png)  

* Concurrency  
    * Thread Safety Problems  
    根据题目，同时打开两个浏览器，一个填写`jeff`，另一个填写`dave`，快速同时点击提交，完成实验  
    ![Thread Safety Problems](./image/thread.png)  
    类似于操作系统讲解的多线程，多线程并发时容易出现错误  
    * Shopping Cart Concurrency Flaw  
    同时打开两个购买界面，界面一选择低价物品，购买但不确认，界面二拼命选择高价商品，刷新自己购物车，在界面一确认，低价购买高价商品成功  
    ![Shopping Cart Concurrency Flaw](./image/shopcart.png)  
    注：参考提示，应该仍然属于线程并发错误（线程并发安全是值得考虑的问题）  

* Insecure Communication  
    * Insecure Login  
    Stage 1:  
    在Burp Suite中可直接查看密码  
    ![Insecure Login Stage 1](./image/inselogin.png)  
    Stage 2:  
    网站改为`https://`无法查看密码  
    ![Insecure Login Stage 2](./image/inselogin2.png)  


##### 问题及解决  
1. 问题：`docker ps`查看docker状态失败  
![docker ps deny](./image/dockerpsdeny.png)  
解决：`sudo chmod 666 /var/run/docker.sock`更改权限  
参考：[How to fix docker: Got permission denied while trying to connect to the Docker daemon socket](https://www.digitalocean.com/community/questions/how-to-fix-docker-got-permission-denied-while-trying-to-connect-to-the-docker-daemon-socket)  
2. 问题：莫名出现查看`docker`为`unhealthy`状态  
![unhealthy状态](./image/unhealthy.png)  
解决：`sudo docker-compose down && sudo docker-compose up -d`  
Tips：重新关起即可解决，难道真的是手气不好？？  

3. VirtualBox配置远程桌面（虽然还是veryvery卡，码在这里）  
    * 虚拟机安装增强功能  
![虚拟机安装增强功能](./image/增强功能.png)  
    * VBoxManage配置远程桌面开放端口  
        ```
        #cmd切换到VirtualBox路径  
        D: //切换到D盘
        cd virtualbox  
        #KKK为待连接虚拟机名称
        #IP地址为当前主机IP地址
        VBoxManage modifyvm "KKK" --vrde on --vrdeport 5050 --vrdeauthtype "null" --vrdeaddress "10.196.16.87"  
        ```  
    * 虚拟机选择**无界面启动**  
    * 远程连接  
    ![远程连接](./image/远程连接.png)  

##### 参考资料  
[网络安全教材第七章](https://c4pr1c3.github.io/cuc-ns/chap0x07/main.html)  
[WebGoat——代码质量、并发、拒绝服务、不当的错误处理](https://blog.csdn.net/lay_loge/article/details/89531924)  
[Virtualbox 内置远程桌面功能使用 Tips](https://gist.github.com/c4pr1c3/691bd2d2532e4d4298fa95e75a2c19ad)  
[2019-NS-Public-chencwx](https://github.com/CUCCS/2019-NS-Public-chencwx/blob/ns_chap0x07/ns_chapter7/Web%20%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E%E6%94%BB%E9%98%B2.md)  






