# SharpGetUserLoginIPRPC

提取域控日志，支持远程提取
核心代码参考及来源：https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E5%9F%BA%E7%A1%80-%E8%8E%B7%E5%BE%97%E5%9F%9F%E7%94%A8%E6%88%B7%E7%9A%84%E7%99%BB%E5%BD%95%E4%BF%A1%E6%81%AF

原作者基础上加了以下功能：

- 按时间筛选
- 按主机筛选
- 按用户筛选
- 支持pth过后查询 （使用当前凭证)
- 工作组用户
- 结构优化

背景：
在域渗透中，获得了域控制器权限后，需要获得域用户的登录信息，包括域用户登录的IP地址和登录时间。通常使用的方法是查看域控制器的登录日志(Eventid=4624)。然而，人工从登录日志(Eventid=4624)中筛选出域用户登录的IP地址和登录时间需要耗费大量时间，不仅无效数据多，而且需要多次判断，所以我们需要编写程序来实现这个功能。

所需条件：域管权限、本地管理员权限

![image](https://user-images.githubusercontent.com/6219246/214342037-afd86ed3-43fb-4668-935d-1bb5db2922cc.png)

![image](https://user-images.githubusercontent.com/6219246/214341722-88ee6d01-fcfd-48c2-b7e6-015a1d3c8dbf.png)
![image](https://user-images.githubusercontent.com/6219246/214341816-29bb7e06-6e2f-4e40-8923-b8cd0e9c60e5.png)


