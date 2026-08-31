# BRATA Keeps Sneaking into Google Play, Now - 分析报告

> **来源**: McAfee
> **发布日期**: APR 12, 2021
> **作者**: Anuradha
> **恶意软件名称**: BRATA Keeps Sneaking into Google Play, Now
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 美国, 巴西
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
BRATA Keeps Sneaking into Google Play, Now
Targeting USA and Spain
Fernando Ruiz APR 12, 2021 12 MIN READ
Recently, the McAfee Mobile Research Team uncovered several new variants of the
Android malware family BRATA being distributed in Google Play, ironically posing as app
security scanners.
These malicious apps urge users to update Chrome, WhatsApp, or a PDF reader, yet
instead of updating the app in question, they take full control of the device by abusing
accessibility services. Recent versions of BRATA were also seen serving phishing
webpages targeting users of financial entities,

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account, clipboard

” (BRATA) by Kaspersky, this “RAT” initially targeted users in Brazil and then rapidly
Products Features Resources About Us Why McAfee Support Log in
evolved into a banking trojan. It combines full device control capabilities with the ability
to display phishing webpages that steal banking credentials in addition to abilities that
allow it capture screen lock credentials (PIN, Password or Pattern), capture keystrokes

Topics At( MkecyAlfoegeger functionality), and record the screen of the infected device to monitor a user’s English

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

d9bc87ab45b0c786aa09f964a8101f6df7ea76895e2e8438c13935a356d9116b com.privacytitan.android 1,000+
f9dc40a7dd2a875344721834e7d80bf7dbfa1bf08f29b7209deb0decad77e992 com.greatvault.mobile 10,000+
e00240f62ec68488ef9dfde705258b025c613a41760138b5d9bdb2fb59db4d5e com.pw.secureshield 5,000+
2846c9dda06a052049d89b1586cff21f44d1d28f153a2ff4726051ac27ca3ba7 com.defensescreen.application 10,000+
URLs:
bialub[.]com
brorne[.]com

Banking trojan functionality: In addition to being able to have full control of the
infected device by abusing accessibility services, BRATA is now serving phishing URLs
based on the presence of certain financial and banking apps defined by the remote
command and control server.
Self-defense techniques: New BRATA variants added new protection layers like
string obfuscation, encryption of configuration files, use of commercial packers, and
the move of its core functionality to a remote server so it can be easily updated

Android malware family BRATA being distributed in Google Play, ironically posing as app
security scanners.
These malicious apps urge users to update Chrome, WhatsApp, or a PDF reader, yet
instead of updating the app in question, they take full control of the device by abusing
accessibility services. Recent versions of BRATA were also seen serving phishing
webpages targeting users of financial entities, not only in Brazil but also in Spain and the
USA.

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

First seen in the wild at the end of 2018 and named “Brazilian Remote Access Tool Android
” (BRATA) by Kaspersky, this “RAT” initially targeted users in Brazil and then rapidly
Products Features Resources About Us Why McAfee Support Log in
evolved into a banking trojan. It combines full device control capabilities with the ability
to display phishing webpages that steal banking credentials in addition to abilities that
allow it capture screen lock credentials (PIN, Password or Pattern), capture keystrokes

First seen in the wild at the end of 2018 and named “Brazilian Remote Access Tool Android
” (BRATA) by Kaspersky, this “RAT” initially targeted users in Brazil and then rapidly
Products Features Resources About Us Why McAfee Support Log in
evolved into a banking trojan. It combines full device control capabilities with the ability
to display phishing webpages that steal banking credentials in addition to abilities that
allow it capture screen lock credentials (PIN, Password or Pattern), capture keystrokes

### 3.4 C2 反检测 (**HIGH**)

based on the presence of certain financial and banking apps defined by the remote
command and control server.
Self-defense techniques: New BRATA variants added new protection layers like
string obfuscation, encryption of configuration files, use of commercial packers, and
the move of its core functionality to a remote server so it can be easily updated
without changing the main application. Some BRATA variants also check first if the
device is worth being attacked before downloading and executing their main

### 3.6 广告欺诈 (**MEDIUM**)

Because BRATA is distributed mainly on Google Play, it allows bad actors to lure victims
into installing these malicious apps pretending that there is a security issue on the
victim’s device and asking to install a malicious app to fix the problem. Given this
common ruse, it is recommended to avoid clicking on links from untrusted sources that
pretend to be a security software which scans and updates your system—e even if that
link leads to an app in Google Play. McAfee offers protection against this threat via
McAfee Mobile Security, which detects this malware as Android/Brata.

### 3.7 蠕虫传播 (**HIGH**)

Recently, the McAfee Mobile Research Team uncovered several new variants of the
Android malware family BRATA being distributed in Google Play, ironically posing as app
security scanners.
These malicious apps urge users to update Chrome, WhatsApp, or a PDF reader, yet
instead of updating the app in question, they take full control of the device by abusing
accessibility services. Recent versions of BRATA were also seen serving phishing
webpages targeting users of financial entities, not only in Brazil but also in Spain and the

### 3.8 权限滥用 (**HIGH**)

security scanners.
These malicious apps urge users to update Chrome, WhatsApp, or a PDF reader, yet
instead of updating the app in question, they take full control of the device by abusing
accessibility services. Recent versions of BRATA were also seen serving phishing
webpages targeting users of financial entities, not only in Brazil but also in Spain and the
USA.
In this blog post we will provide an overview of this threat, how does this malware

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.defensescreen.application` | 域名类型 |
| `com.greatvault.mobile` | 域名类型 |
| `com.outprotect.android` | 域名类型 |
| `com.privacytitan.android` | 域名类型 |
| `com.pw.secureshield` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `2846c9dda06a052049d89b1586cff21f44d1d28f153a2ff4726051ac27ca3ba7` | 恶意文件 |
| `4cdbd105ab8117620731630f8f89eb2e6110dbf6341df43712a0ec9837c5a9be` | 恶意文件 |
| `d9bc87ab45b0c786aa09f964a8101f6df7ea76895e2e8438c13935a356d9116b` | 恶意文件 |
| `e00240f62ec68488ef9dfde705258b025c613a41760138b5d9bdb2fb59db4d5e` | 恶意文件 |
| `f9dc40a7dd2a875344721834e7d80bf7dbfa1bf08f29b7209deb0decad77e992` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): config_update
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
