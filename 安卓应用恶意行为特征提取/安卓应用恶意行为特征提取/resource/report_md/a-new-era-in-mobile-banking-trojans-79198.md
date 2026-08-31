# A new era in mobile banking Trojans - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: ROMAN UNUCHEK
> **恶意软件名称**: A new era in mobile banking Trojans
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯, 土耳其
| 活动时间 | 未知
| 传播方式 | 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
A new era in mobile banking Trojans
MALWARE DESCRIPTIONS 31 JUL 2017 3 minute read
// AUTHORS
ROMAN UNUCHEK
Svpeng turns keylogger and steals everything through
accessibility services
In mid-July 2017, we found a new modification of the well-known mobile banking malware family
Svpeng – Trojan-Banker.AndroidOS.Svpeng.ae. In this modification, the cybercriminals have added
new functionality: it now also works as a keylogger, stealing entered text through the use of
accessibility services.
Accessibility services generally provide user interface (UI) enhancements for users with disabiliti

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account

MALWARE DESCRIPTIONS 31 JUL 2017 3 minute read
// AUTHORS
ROMAN UNUCHEK
Svpeng turns keylogger and steals everything through
accessibility services
In mid-July 2017, we found a new modification of the well-known mobile banking malware family
Svpeng – Trojan-Banker.AndroidOS.Svpeng.ae. In this modification, the cybercriminals have added

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

[Page 6]
MD5
F536BC5B79C16E9A84546C2049E810E1
GOOGLE ANDROID MOBILE MALWARE TROJAN BANKER
A new era in mobile banking Trojans
Your email address will not be published. Required fields are marked *

services too. Leaking ads

[Page 4]
From the information Svpeng receives from its command and control server (CnC), I was able to
intercept an encrypted configuration file and decrypt it to find out the attacked apps, and to
Pocket cryptofarms
obtain a URL with phishing pages.

services too. Leaking ads

[Page 4]
From the information Svpeng receives from its command and control server (CnC), I was able to
intercept an encrypted configuration file and decrypt it to find out the attacked apps, and to
Pocket cryptofarms
obtain a URL with phishing pages.

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

[Page 1]
A new era in mobile banking Trojans
MALWARE DESCRIPTIONS 31 JUL 2017 3 minute read
// AUTHORS
ROMAN UNUCHEK

[Page 1]
A new era in mobile banking Trojans
MALWARE DESCRIPTIONS 31 JUL 2017 3 minute read
// AUTHORS
ROMAN UNUCHEK

### 3.4 C2 反检测 (**HIGH**)

[Page 4]
From the information Svpeng receives from its command and control server (CnC), I was able to
intercept an encrypted configuration file and decrypt it to find out the attacked apps, and to
Pocket cryptofarms
obtain a URL with phishing pages.
I uncovered a few antivirus apps that the Trojan attempted to block, and some apps with phishing

users were in Russia (29%), Germany (27%), Turkey (15%), Poland (6%) and France (3%). It is worth
BORIS LARIN,DENIS LEGEZO
noting that, even though most attacked users are from Russia, this Trojan won’t work on devices
running the Russian language. This is a standard tactic for Russian cybercriminals looking to evade
detection and arrest. 26 FEB 2021, 12:00PM
GReAT Ideas. Green Tea Edition
The Svpeng malware family is known for being innovative. Starting from 2013, it was among the first JOHN HULTQUIST,BRIAN BARTHOLOMEW,SUGURU ISHIMARU,

### 3.5 勒索软件 (**HIGH**)

To collect info (Contacts, installed apps and call logs)
Ymir: new stealthy
To collect all SMS from the device
ransomware in the wild
To open URL
To start stealing incoming SMS QSC: A multi-plugin
framework used by

### 3.7 蠕虫传播 (**HIGH**)

GReAT Ideas. Green Tea Edition
The Svpeng malware family is known for being innovative. Starting from 2013, it was among the first JOHN HULTQUIST,BRIAN BARTHOLOMEW,SUGURU ISHIMARU,
VITALY KAMLUK,SEONGSU PARK,YUSUKE NIWA,
to begin attacking SMS banking, to use phishing pages to overlay other apps to steal credentials,
MOTOHIKO SATO
and to block devices and demand money. In 2016, cybercriminals were actively distributing Svpeng
through AdSense using a vulnerability in the Chrome browser. This makes Svpeng one of the most

### 3.8 权限滥用 (**HIGH**)

// AUTHORS
ROMAN UNUCHEK
Svpeng turns keylogger and steals everything through
accessibility services
In mid-July 2017, we found a new modification of the well-known mobile banking malware family
Svpeng – Trojan-Banker.AndroidOS.Svpeng.ae. In this modification, the cybercriminals have added
new functionality: it now also works as a keylogger, stealing entered text through the use of

GReAT Ideas. Green Tea Edition
The Svpeng malware family is known for being innovative. Starting from 2013, it was among the first JOHN HULTQUIST,BRIAN BARTHOLOMEW,SUGURU ISHIMARU,
VITALY KAMLUK,SEONGSU PARK,YUSUKE NIWA,
to begin attacking SMS banking, to use phishing pages to overlay other apps to steal credentials,
MOTOHIKO SATO
and to block devices and demand money. In 2016, cybercriminals were actively distributing Svpeng
through AdSense using a vulnerability in the Chrome browser. This makes Svpeng one of the most

[Page 8]
HoneyMyte updates CoolClient and The HoneyMyte APT evolves with a kernel-
deploys multiple stealers in recent mode rootkit and a ToneShell backdoor
campaigns
Kaspersky discloses a 2025 HoneyMyte (aka
Kaspersky researchers analyze updated

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

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
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
8. 其他行为见详细信息...
