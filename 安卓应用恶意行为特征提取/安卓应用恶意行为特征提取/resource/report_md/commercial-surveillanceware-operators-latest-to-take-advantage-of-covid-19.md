# March 18, 2020 - 分析报告

> **来源**: Lookout
> **发布日期**: 未知
> **作者**: Kristin Del Rosso
> **恶意软件名称**: March 18, 2020
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等)
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Lookout Research Threat Guidances Threat Data Resources About Us Contact Us
March 18, 2020
Commercial Surveillanceware Operators
Exploit COVID-19
As COVID-19 spreads and individuals seek accurate information about the virus and its impacts,
governments and businesses are extensively using email, text messages, and other digital tools to
communicate with citizens and customers alike. Unfortunately, cybercriminals and scammers have taken
[Page 2]
advantage of the increase in communication around this topic, as well as individuals’ desires to stay up to
date, find health tips, or track t

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

and the ability to remotely activate the microphone and cameras.
SpyNote Permissions
While this “corona live 1.1” application itself appears to be waiting for more functionality, it stores command
and control (C2) information in resources/values/strings as is common in SpyMax and SpyNote samples,
where it contains the hard-coded address of the attacker’s server.
Pivoting off of the domain of the C2 server enabled Lookout researchers to find 30 unique APKs that share
infrastructure in what appears to be a larger surveillance campaign that has been ongoing since at least

SpyMax allows the actor to access a variety of sensitive data on the phone, and provides a shell terminal
and the ability to remotely activate the microphone and cameras.
SpyNote Permissions
While this “corona live 1.1” application itself appears to be waiting for more functionality, it stores command
and control (C2) information in resources/values/strings as is common in SpyMax and SpyNote samples,
where it contains the hard-coded address of the attacker’s server.
Pivoting off of the domain of the C2 server enabled Lookout researchers to find 30 unique APKs that share

and the ability to remotely activate the microphone and cameras.
SpyNote Permissions
While this “corona live 1.1” application itself appears to be waiting for more functionality, it stores command
and control (C2) information in resources/values/strings as is common in SpyMax and SpyNote samples,
where it contains the hard-coded address of the attacker’s server.
Pivoting off of the domain of the C2 server enabled Lookout researchers to find 30 unique APKs that share
infrastructure in what appears to be a larger surveillance campaign that has been ongoing since at least

### 3.6 广告欺诈 (**MEDIUM**)

used against us for malicious ends. Furthermore, the commercialization of “off-the-shelf” spyware kits
makes it fairly easy for these malicious actors to spin up these bespoke campaigns almost as quickly as a
crisis like COVID-19 takes hold. These applications were never available in the Google Play store. It is
important to avoid downloading apps from third-party app stores and clicking suspicious links for
“informative” sites or apps spread via SMS.
IOCs
Android Applications

### 3.7 蠕虫传播 (**HIGH**)

March 18, 2020
Commercial Surveillanceware Operators
Exploit COVID-19
As COVID-19 spreads and individuals seek accurate information about the virus and its impacts,
governments and businesses are extensively using email, text messages, and other digital tools to
communicate with citizens and customers alike. Unfortunately, cybercriminals and scammers have taken

makes it fairly easy for these malicious actors to spin up these bespoke campaigns almost as quickly as a
crisis like COVID-19 takes hold. These applications were never available in the Google Play store. It is
important to avoid downloading apps from third-party app stores and clicking suspicious links for
“informative” sites or apps spread via SMS.
IOCs
Android Applications
TITLE PACKAGE NAME SHA1

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `102.69.43` | 域名类型 |
| `165.16.67` | 域名类型 |
| `165.16.76` | 域名类型 |
| `198.54.116` | 域名类型 |
| `41.252.129` | 域名类型 |
| `41.252.165` | 域名类型 |
| `41.252.173` | 域名类型 |
| `41.253.17` | 域名类型 |
| `41.253.23` | 域名类型 |
| `41.253.48` | 域名类型 |
| `41.253.52` | 域名类型 |
| `41.253.61` | 域名类型 |
| `62.240.51` | 域名类型 |
| `82.205.176` | 域名类型 |
| `a.stub.suffix` | 域名类型 |
| `package.name.suffix` | 域名类型 |
| `yps.eton.application` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等) |
| **综合风险** | **CRITICAL** | 检测到3类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **广告欺诈** (MEDIUM): 发现
3. **蠕虫传播** (HIGH): 发现
