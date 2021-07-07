# FAPI

本目录基于tpm2-tss软件栈中fapi软件层进行tpm的练习交互使用

## 简述FAPI层

TSS2.0中的FAPI( Feature API)是非常高级的API,类似于使用Java,Golang一样方便,大多数应用层的程序都可以基于此层进行开发.

TSS的FAPI目标是让用户更加简单的使用TPM2.0最常用的功能.因此,FAPI并不能使用TPM的一些特殊功能.

设计者在设计FAPI层的时候,就是希望80%的应用程序定义最少的参数就能使用FAPI层满足他们的使用需求,而不去使用其他TSS API.

当然要想实现这种方式,就是使用一个配置文件来定义用户对算法,密钥大小,加密模式,签名模式等的默认配置,用户在创建密钥的时候就可以使用这些默认的配置.

[配置文件规范链接](https://trustedcomputinggroup.org/wp-content/uploads/TSS_JSON_Policy_v0p7_r08_pub.pdf)