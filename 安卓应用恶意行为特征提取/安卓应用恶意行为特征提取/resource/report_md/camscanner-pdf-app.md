# Downloaded CamScanner - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Downloaded CamScanner
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等)
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
gbhackers.
Malware
Beware!! 100 Million Users
Downloaded CamScanner
PDF App Drops a Malware in
Android Phone
ByBalaji August 28, 2019
Its time to uninstall the CamScanner App from your Android Phone. 
[Page 2]
Yes, dangerogus bmahlwaare ccomkpeonernst fo.und in popular phone PDF
creator app “CamScanner” that downloaded over 100 million Android
users from Google Playstore.
CamScanner is one of the most popular documents scanning apps
that convert any printed document to a PDF file, and the app
developed and maintained by INTSIG Information Co., Ltd.
Security researchers noticed that t

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

control server and executes the code to download and launch the
payload from the malicious server.
Malware motivation believed to silently take control of the
victims Android devices and stealing money by delivering
aggressive advertising and encourage users to subscribe
to the paid utilities.
Researchers from Kaspersky detected this malware as Trojan-

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

cdf045f1d96fae53d3986b985d787b59
9fbc7c3c3326bfc710f9b079766cf85c
2087986583416f45ae411ebd8c5db8aa
a1b3551ec1dcdce7ac2655994697a02d
d0ae4282d629518458fb5ca765627a71
d28ec38edda65324299fc0dcddca9740
2e9eef8b88bf942e416ed244a427d20c

In the next steps, a configuration file called “comparison” is
decrypted and it reveals the configuration with the addresses of the
attackers’ servers.
Later it downloads additional modules from the command and
control server and executes the code to download and launch the
payload from the malicious server.
Malware motivation believed to silently take control of the

decrypted and it reveals the configuration with the addresses of the
attackers’ servers.
Later it downloads additional modules from the command and
control server and executes the code to download and launch the
payload from the malicious server.
Malware motivation believed to silently take control of the
victims Android devices and stealing money by delivering

### 3.5 勒索软件 (**HIGH**)

Also Read:
Malware-as-a-service – Adwind Malware Attack Utilities Industry Via
Weaponized PDF File
Shade Ransomware Attack Enterprise Networks through Weaponized
PDF Files & Malspam Emails 

[Page 5]

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等) |
| **综合风险** | **CRITICAL** | 检测到3类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): 发现
2. **远程控制** (CRITICAL): config_update
3. **勒索软件** (HIGH): 发现
