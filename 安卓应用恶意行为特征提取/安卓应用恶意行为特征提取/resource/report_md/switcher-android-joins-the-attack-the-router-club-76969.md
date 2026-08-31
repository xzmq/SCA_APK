# Switcher: Android joins the ‘attack-the-router’ club - 分析报告

> **来源**: Securelist
> **发布日期**: 未知
> **作者**: NIKITA BUCHKA
> **恶意软件名称**: Switcher: Android joins the ‘attack-the-router’ club
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Switcher: Android joins the ‘attack-the-router’ club
MALWARE DESCRIPTIONS 28 DEC 2016 4 minute read
// AUTHORS
NIKITA BUCHKA
Recently, in our never-ending quest to protect the world from malware, we found a misbehaving
Android trojan. Although malware targeting the Android OS stopped being a novelty quite some
time ago, this trojan is quite unique. Instead of attacking a user, it attacks the Wi-Fi network the
user is connected to, or, to be precise, the wireless router that serves the network. The trojan,
dubbed Trojan.AndroidOS.Switcher, performs a brute-force password guessing attac

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: contacts, account

GOOGLE ANDROID MOBILE MALWARE DNS ROUTER
Switcher: Android joins the ‘attack-the-router’ club
Your email address will not be published. Required fields are marked * IN THE SAME CATEGORY
Type your comment here Lumma Stealer – Tracking
distribution channels
Name * Email * Download a banker to track
your parcel

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

infection.
The cybercriminals even created a website (though badly made) to advertise and distribute the
aforementioned fake version of com.snda.wifilocating. The web server that hosts the site is also
used by the malware authors as the command-and-control (C&C) server.

[Page 3]
Table of Contents

infection.
The cybercriminals even created a website (though badly made) to advertise and distribute the
aforementioned fake version of com.snda.wifilocating. The web server that hosts the site is also
used by the malware authors as the command-and-control (C&C) server.

[Page 3]
Table of Contents

infection.
The cybercriminals even created a website (though badly made) to advertise and distribute the
aforementioned fake version of com.snda.wifilocating. The web server that hosts the site is also
used by the malware authors as the command-and-control (C&C) server.

[Page 3]
Table of Contents

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

Your email address will not be published. Required fields are marked * IN THE SAME CATEGORY
Type your comment here Lumma Stealer – Tracking
distribution channels
Name * Email * Download a banker to track
your parcel
Analysis of Elpaco: a Mimic
variant

### 3.4 C2 反检测 (**HIGH**)

to deliver MgBot what changed
Kaspersky GReAT experts analyze the Evasive Kaspersky expert describes new malicious tools
Panda APT’s infection chain, including shellcode employed by the Cloud Atlas APT, including
encrypted with DPAPI and RC5, as well as the implants of their signature backdoors
MgBot implant. VBShower, VBCloud, PowerShower, and
CloudAtlas.

### 3.5 勒索软件 (**HIGH**)

Comment
This site uses Akismet to reduce spam. Learn how your comment data is processed.
Ymir: new stealthy
MELANIE ransomware in the wild
Posted on January 5, 2017. 4:24 pm
Is it possible to update the phone’s firmware to patch this security issue? Perhaps a better
QSC: A multi-plugin

### 3.7 蠕虫传播 (**HIGH**)

for sharing information about Wi-Fi networks (including the security password) between users of
the app. Such information is used, for example, by business travelers to connect to a public Wi-Fi
network for which they don’t know the password. It is a good place to hide malware targeting
routers, because users of such apps usually connect with many Wi-Fi networks, thus spreading the
infection.
The cybercriminals even created a website (though badly made) to advertise and distribute the
aforementioned fake version of com.snda.wifilocating. The web server that hosts the site is also

### 3.8 权限滥用 (**HIGH**)

KSENIYA KUDASHEVA FABIO ASSOLINI
// REPORTS
HoneyMyte updates CoolClient and The HoneyMyte APT evolves with a kernel-
deploys multiple stealers in recent mode rootkit and a ToneShell backdoor
campaigns
Kaspersky discloses a 2025 HoneyMyte (aka
Kaspersky researchers analyze updated

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `101.200.147.153` | 域名类型 |
| `112.33.13.11` | 域名类型 |
| `120.76.249.59` | 域名类型 |
| `87.245.200.153` | 域名类型 |
| `com.baidu.com` | 域名类型 |
| `com.snda.wifi` | 域名类型 |
| `com.snda.wifilocating` | 域名类型 |
| `m.baidu.com` | 域名类型 |
| `www.coolapk.com` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `101.200.147.153` | 服务器 |
| `112.33.13.11` | 服务器 |
| `120.76.249.59` | 服务器 |
| `8.8.8.8` | 服务器 |
| `87.245.200.153` | 服务器 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `http://m.baidu.com` | 钓鱼/下载 |
| `http://www.coolapk.com/apk/com.snda.wifilocating` | 钓鱼/下载 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @101 | C2/通信 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): contacts, account
2. **远程控制** (CRITICAL): config_update
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
8. 其他行为见详细信息...
