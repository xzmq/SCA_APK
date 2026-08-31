# Back to Cybereason.com - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: Daniel Frank
> **恶意软件名称**: Back to Cybereason.com
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 美国, 欧洲
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Back to Cybereason.com
Subscribe
All Research Podcasts Webinars Resources Videos News
Search Subscribe
EventBot: A New Mobile Banking Trojan is Born
WRITTEN BY Cybereason Nocturnus Cookies Settings Reject All
By clicking “Accept All Cookies”, you agree to the storing of cookies on your device to enhance site navigation, analyze site usage, and
assist in our marketing efforts.
Research by: Daniel Frank, Lior Rochberger, Yaron Rimmer and Assaf Dahan
Accept All Cookies
X
Want to see the Cybereason Defense Platform in action? Schedule a Demo
[Page 2]
KEY FINDINGS
Back to Cybereason.com
Th

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account, device_info

Back to Cybereason.com
The Cybereason Nocturnus team is investigating EventBot, a new type of Android mobile malware that emerged around
March 2020. EventBot is a mobile banking trojan and infostealer that abuses Android’s accessibility features to steal user
data from financial applications, read user SMS messages, and steal SMS messages to allow the malware to bypass two-
factor authentication.
EventBot targets users of over 200 different financial applications, including banking, money transfer services, and

Information gathered about the infected device to be sent to the C2.

Back to Cybereason.com
Data encryption: In the initial version of EventBot, the data being exfiltrated is encrypted using Base64 and
RC4. In later versions, another encryption layer is added using Curve25519 encryption. All of the most recent
versions of EventBot contain a ChaCha20 library that can improve performance when compared to other
algorithms like RC4 and AES. This implies that the authors are actively working to optimize EventBot over time.

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

[Page 9]
By analyzing and decoding the HTTP packets in EventBot Version 0.0.0.1, we can see that EventBot downloads and updates a

configuration file with almost 200 different financial application targets. Following is the HTTP response from the C2 servBear,ck to Cybereason.com
containing the encrypted configuration:
Encrypted HTTP response returned from the C2.
In Version 0.0.0.1, the communication with the C2 is encrypted using Base64 and RC4. The RC4 key is hardcoded in EventBot.

Back to Cybereason.com
Web injects execution method by a pre-established configuration.
BOT UPDATES
EventBot has a long method called parseCommand that can update EventBotʼs configuration XML files, located in the shared
preferences folder on the device.
Dropped XML configuration files on the device.
EventBot uses this function to update its C2s, the configuration of webinjects, etc. The following code shows EventBot parsing

### 3.3 银行木马 (**CRITICAL**)

Subscribe
All Research Podcasts Webinars Resources Videos News
Search Subscribe
EventBot: A New Mobile Banking Trojan is Born
WRITTEN BY Cybereason Nocturnus Cookies Settings Reject All
By clicking “Accept All Cookies”, you agree to the storing of cookies on your device to enhance site navigation, analyze site usage, and
assist in our marketing efforts.

Subscribe
All Research Podcasts Webinars Resources Videos News
Search Subscribe
EventBot: A New Mobile Banking Trojan is Born
WRITTEN BY Cybereason Nocturnus Cookies Settings Reject All
By clicking “Accept All Cookies”, you agree to the storing of cookies on your device to enhance site navigation, analyze site usage, and
assist in our marketing efforts.

Grabbing the Screen PIN with Support for Samsung Devices
Version 0.3.0.1 added an ~800 line long method called grabScreenPin, which uses accessibility features to track pin code
changes in the deviceʼs settings. It listens to events like TYPE_VIEW_TEXT_CHANGED. We suspect the updated PIN is sent to
the C2, most likely to give the malware the option to perform privileged activities on the infected device related to payments,
system configuration options, etc.
Listening to TYPE_VIEW_TEXT_CHANGED accessibility event.
After collecting the changed PIN code, it is sent back to the C2.

### 3.4 C2 反检测 (**HIGH**)

By analyzing and decoding the HTTP packets in EventBot Version 0.0.0.1, we can see that EventBot downloads and updates a

configuration file with almost 200 different financial application targets. Following is the HTTP response from the C2 servBear,ck to Cybereason.com
containing the encrypted configuration:
Encrypted HTTP response returned from the C2.
In Version 0.0.0.1, the communication with the C2 is encrypted using Base64 and RC4. The RC4 key is hardcoded in EventBot.
Upon decryption, we can see that the response from the server is a JSON object of EventBotʼs configuration, which contains

### 3.6 广告欺诈 (**MEDIUM**)

Search Subscribe
EventBot: A New Mobile Banking Trojan is Born
WRITTEN BY Cybereason Nocturnus Cookies Settings Reject All
By clicking “Accept All Cookies”, you agree to the storing of cookies on your device to enhance site navigation, analyze site usage, and
assist in our marketing efforts.
Research by: Daniel Frank, Lior Rochberger, Yaron Rimmer and Assaf Dahan
Accept All Cookies

### 3.7 蠕虫传播 (**HIGH**)

Back to Cybereason.com
The Cybereason Nocturnus team is investigating EventBot, a new type of Android mobile malware that emerged around
March 2020. EventBot is a mobile banking trojan and infostealer that abuses Android’s accessibility features to steal user
data from financial applications, read user SMS messages, and steal SMS messages to allow the malware to bypass two-
factor authentication.
EventBot targets users of over 200 different financial applications, including banking, money transfer services, and
crypto-currency wallets. Those targeted include applications like Paypal Business, Revolut, Barclays, UniCredit,

### 3.8 权限滥用 (**HIGH**)

Back to Cybereason.com
The Cybereason Nocturnus team is investigating EventBot, a new type of Android mobile malware that emerged around
March 2020. EventBot is a mobile banking trojan and infostealer that abuses Android’s accessibility features to steal user
data from financial applications, read user SMS messages, and steal SMS messages to allow the malware to bypass two-
factor authentication.
EventBot targets users of over 200 different financial applications, including banking, money transfer services, and

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `185.158.24` | 域名类型 |
| `208.91.197` | 域名类型 |
| `31.214.157` | 域名类型 |
| `com.example.eventbot` | 域名类型 |
| `com.example.eventbotʼ` | 域名类型 |
| `frfxorct.sr.xcoordinator` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `0.0.0.1` | 服务器 |
| `0.0.0.2` | 服务器 |
| `0.3.0.1` | 服务器 |
| `0.4.0.1` | 服务器 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): config_update
3. **银行木马** (CRITICAL): 发现
4. **C2 反检测** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
