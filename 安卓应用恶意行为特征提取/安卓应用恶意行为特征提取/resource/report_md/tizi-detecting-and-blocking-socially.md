# Security Blog - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: attempt to install their
> **恶意软件名称**: Security Blog
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Security Blog
The latest news and insights from Google on security and safety on the Internet
[Page 2]
Tizi: Detecting and blocking socially engineered spyware on
Search blog ...
Android
November 27, 2017
Labels 
Posted by Anthony Desnos, Megan Ruthven, and Richard Neal, Google Play Protect security engineers and  Archive 
Clement Lecigne, Threat Analysis Group
Feed
Google is constantly working to improve our systems that protect users from
Google
Potentially Harmful Applications (PHAs). Usually, PHA authors attempt to install their
YouTube 14M
harmful apps on as many devices as po

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account

teams worked together to detect and investigate Tizi-infected apps and remove and
block them from Android devices.
What is Tizi?
Tizi is a fully featured backdoor that installs spyware to steal sensitive data from
popular social media applications. The Google Play Protect security team discovered
this family in September 2017 when device scans found an app with rooting
capabilities that exploited old vulnerabilities. The team used this app to find more

### 3.2 远程控制 (**CRITICAL**)

468fdb9b3e4c950dce5b35d4567b47 32a96e243201
d4a7
com.dailyworkout.tizi 7c6af091a7b0f04fb5b212bd3c180d 404b4d1a7176e219eaa457b0050b
dcc6abf7cd77478fd22595e5b7aa7c 4081c22a9a1a
fd9f
com.system.update.systemupdate 7a956c754f003a219ea1d2205de 4d2962ac1f6551435709a5a87459
3ef 5d855b1fa8ab

rooting capabilities or obfuscation, but later variants did.
After gaining root, Tizi steals sensitive data from popular social media apps like
Facebook, Twitter, WhatsApp, Viber, Skype, LinkedIn, and Telegram. It usually first
contacts its command-and-control servers by sending an SMS with the device's GPS
coordinates to a specific number. Subsequent command-and-control communications
are normally performed over regular HTTPS, though in some specific versions, Tizi uses
the MQTT messaging protocol with a custom server. The backdoor contains various

rooting capabilities or obfuscation, but later variants did.
After gaining root, Tizi steals sensitive data from popular social media apps like
Facebook, Twitter, WhatsApp, Viber, Skype, LinkedIn, and Telegram. It usually first
contacts its command-and-control servers by sending an SMS with the device's GPS
coordinates to a specific number. Subsequent command-and-control communications
are normally performed over regular HTTPS, though in some specific versions, Tizi uses
the MQTT messaging protocol with a custom server. The backdoor contains various

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter, forum

the MQTT messaging protocol with a custom server. The backdoor contains various
capabilities common to commercial spyware, such as recording calls from WhatsApp,
Viber, and Skype; sending and receiving SMS messages; and accessing calendar
events, call log, contacts, photos, Wi-Fi encryption keys, and a list of all installed apps.
Tizi apps can also record ambient audio and take pictures without displaying the image
on the device's screen.
Tizi can root the device by exploiting one of the following local vulnerabilities:

### 3.7 蠕虫传播 (**HIGH**)

backdoor PHAs without connecting them as a family. The early Tizi variants didn't have
rooting capabilities or obfuscation, but later variants did.
After gaining root, Tizi steals sensitive data from popular social media apps like
Facebook, Twitter, WhatsApp, Viber, Skype, LinkedIn, and Telegram. It usually first
contacts its command-and-control servers by sending an SMS with the device's GPS
coordinates to a specific number. Subsequent command-and-control communications
are normally performed over regular HTTPS, though in some specific versions, Tizi uses

recommend these 5 basic steps:
Check permissions: Be cautious with apps that request unreasonable
permissions. For example, a flashlight app shouldn't need access to send
SMS messages.
Enable a secure lock screen: Pick a PIN, pattern, or password that is easy
for you to remember and hard for others to guess.
Update your device: Keep your device up-to-date with the latest security

### 3.8 权限滥用 (**HIGH**)

FFoollllooww
number of devices to achieve a certain goal.
Give us feedback in our Product
This blog post covers Tizi, a backdoor family with some rooting capabilities that was
Forums.
used in a targeted attack against devices in African countries, specifically: Kenya,
Nigeria, and Tanzania. We'll talk about how the Google Play Protect and Threat Analysis

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.dailyworkout.tizi` | 域名类型 |
| `com.press.nasa.com.tanofresh` | 域名类型 |
| `com.system.update.systemupdate` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `4d0887f41d0de2f31459c14e3133debcdf758ad8bbe57128d3bec2c907f2acf3` | 恶意文件 |
| `9869871ed246d5670ebca02bb265a584f998f461db0283103ba58d4a650333be` | 恶意文件 |
| `f2e45ea50fc71b62d9ea59990ced755636286121437ced6237aff90981388f6a` | 恶意文件 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @ggooooggllee | C2/通信 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): 发现
3. **C2 反检测** (HIGH): twitter, forum
4. **蠕虫传播** (HIGH): 发现
5. **权限滥用** (HIGH): 发现
