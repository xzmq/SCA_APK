# By Dario Durando| November 08, 2017 - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: likely receives revenue every time an ad
> **恶意软件名称**: By Dario Durando| November 08, 2017
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
FFOORRTTIIGGUUAARRDD LLAABBSS TTHHRREEAATT RREESSEEAARRCCHH
TThhee SSttrraannggee CCaassee ooff PPllaayy PPoolliiccyy ffoorr CCooppyyrriigghhtt aanndd
SSeeccuurriittyy
By Dario Durando| November 08, 2017
Google Play is the primary Android application marketplace. It contains roughly 3.5 million applications. Every day, this number increases thanks to a
multitude of talented developers that upload new apps to the platform.
Unfortunately, not all developers have the best intentions in mind. Malicious software is often found on Google Play impersonating innocuous
applications (ranging fr

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

Note: Following some tweets published during the weekend, these applications have been taken down from the Google Play store while the
blogpost was under review.
IOC:
Sample 1: 80fe0de24e58eb1c485d55c94d20ffd710fc4b8a05f2c20d9d0d42cabb683fad
Sample 2: 9c3c61fc222250d030d96316d794050160082980d7c1058b403a04dddedcfe7c
Sample 3: fed42f25688b310313da4217460fa999b980f325a86971a6e0a9f0327a9567b6
Sample 4: f455599f5043c212e29a62ea3e3c3c14a9ad8ceec998f7ed0aa690ba9dfc328f

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: overlay

[Page 9]
The app demonstrates the process of how to install a third party application by allowing unknown sources and then installing the apk manually.
The link used by the downloader could also be easily substituted with a link to a malicious android apk, a banker, or a ransomware, and in that case
the user would be completely powerless, and even worse, he would have installed that dangerous software on his/her device himself.
Conclusion
From what I could observe, none of these applications are complying with Google terms and policies about the impersonation of intellectual

### 3.5 勒索软件 (**HIGH**)

[Page 9]
The app demonstrates the process of how to install a third party application by allowing unknown sources and then installing the apk manually.
The link used by the downloader could also be easily substituted with a link to a malicious android apk, a banker, or a ransomware, and in that case
the user would be completely powerless, and even worse, he would have installed that dangerous software on his/her device himself.
Conclusion
From what I could observe, none of these applications are complying with Google terms and policies about the impersonation of intellectual

### 3.7 蠕虫传播 (**HIGH**)

multitude of talented developers that upload new apps to the platform.
Unfortunately, not all developers have the best intentions in mind. Malicious software is often found on Google Play impersonating innocuous
applications (ranging from utility tools to games to system updates.)
Recently, the FortiGuard Labs team noticed that one of the most successful applications on the market, “WhatsAppMessenger” developed by
“WhatsApp Inc.”, has been the target of a lot of attention by scammers and criminals alike.

[Page 2]

multitude of talented developers that upload new apps to the platform.
Unfortunately, not all developers have the best intentions in mind. Malicious software is often found on Google Play impersonating innocuous
applications (ranging from utility tools to games to system updates.)
Recently, the FortiGuard Labs team noticed that one of the most successful applications on the market, “WhatsAppMessenger” developed by
“WhatsApp Inc.”, has been the target of a lot of attention by scammers and criminals alike.

[Page 2]

### 3.8 权限滥用 (**HIGH**)

This kind of application is the most common impersonator for legitimate apps. An update downloader that in reality generates revenue for the
creator, but delivers nothing to the user.
Samples 2 and 3
These next samples again display a large amount of very intrusive overlays, ranging from ads of big brands to redirecting to the download page of
other apps on the play store. I grouped them together because their package names - update.app11213 and update.app21153 - look a lot alike,
possibly being iterations of a computer-generated name.

THREAT RESEARCH
Android/BondPath: a Mature Spyware
THREAT RESEARCH
Unmasking Android Malware: A Deep Dive into a New Rootnik Variant, Part I
THREAT RESEARCH
Cookie Maker: Inside the Google Docs Malicious Network

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `startapp.android.publish` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `80fe0de24e58eb1c485d55c94d20ffd710fc4b8a05f2c20d9d0d42cabb683fad` | 恶意文件 |
| `9c3c61fc222250d030d96316d794050160082980d7c1058b403a04dddedcfe7c` | 恶意文件 |
| `f455599f5043c212e29a62ea3e3c3c14a9ad8ceec998f7ed0aa690ba9dfc328f` | 恶意文件 |
| `fed42f25688b310313da4217460fa999b980f325a86971a6e0a9f0327a9567b6` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **银行木马** (CRITICAL): overlay
3. **勒索软件** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
5. **权限滥用** (HIGH): 发现
