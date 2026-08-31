# By: Kevin Sun - 分析报告

> **来源**: Trend Micro
> **发布日期**: Sep 13, 2017
> **作者**: Kevin Sun
Sep
> **恶意软件名称**: By: Kevin Sun
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Mobile
BankBot Seen on Google Play, Targets New UAE Bank Apps
We found five new Bankbot apps, four of which made their way into the Google Play Store disguised as utility apps. Two were made available long enough to be downloaded by a few
users; one particular BankBot app was downloaded 5000-10000 times.
By: Kevin Sun
Sep 13, 2017
Read time: 4 min (953 words)
Updated September 15, 2017 3:45 AM to modify some sentences, further clarifying technical
concepts.
The Android-targeting BankBot malware (all variants detected by Trend Micro as
ANDROIDOS_BANKBOT) first surfaced January of this 

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, account

ANDROIDOS_BANKBOT) first surfaced January of this year and is reportedly the improved
version of an unnamed open source banking malware that was leaked in an underground
hacking forum. BankBot is particularly risky because it disguises itself as legitimate banking apps,
typically using fake overlay screens to mimic existing banking apps and steal user credentials.
BankBot is also capable of hijacking and intercepting SMS messages, which means that it can
bypass SMS-based 2-factor authentication.

### 3.2 远程控制 (**CRITICAL**)

AE0C7562F50E640B81646B3553EB0A6381DAC66D015BAA0FA95E136D2DC855F7

CF46FDC278DC9D29C66E40352340717B841EAF447F4BEDDF33A2A21678B64138

DE2367C1DCD67C97FCF085C58C15B9A3311E61C122649A53DEF31FB689E1356F

New BankBot details and analysis
When BankBot is installed and running, it will check the package information of apps installed on
the infected device. If one of the target bank apps is available, BankBot will connect to its C&C
server and upload the target’s package name and label. The C&C server will send a URL to 
BankBot so it can download the library that contains files used for the overlay webpage. This
overly page is displayed on top of the legitimate banking app and used to steal the user’s

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: overlay

concepts.
The Android-targeting BankBot malware (all variants detected by Trend Micro as
ANDROIDOS_BANKBOT) first surfaced January of this year and is reportedly the improved
version of an unnamed open source banking malware that was leaked in an underground
hacking forum. BankBot is particularly risky because it disguises itself as legitimate banking apps,
typically using fake overlay screens to mimic existing banking apps and steal user credentials.
BankBot is also capable of hijacking and intercepting SMS messages, which means that it can

[Page 1]
Mobile
BankBot Seen on Google Play, Targets New UAE Bank Apps
We found five new Bankbot apps, four of which made their way into the Google Play Store disguised as utility apps. Two were made available long enough to be downloaded by a few
users; one particular BankBot app was downloaded 5000-10000 times.
By: Kevin Sun

### 3.7 蠕虫传播 (**HIGH**)

version of an unnamed open source banking malware that was leaked in an underground
hacking forum. BankBot is particularly risky because it disguises itself as legitimate banking apps,
typically using fake overlay screens to mimic existing banking apps and steal user credentials.
BankBot is also capable of hijacking and intercepting SMS messages, which means that it can
bypass SMS-based 2-factor authentication.

Throughout the year, Bankbot has been distributed as benign apps, some of which made their

### 3.8 权限滥用 (**HIGH**)

ANDROIDOS_BANKBOT) first surfaced January of this year and is reportedly the improved
version of an unnamed open source banking malware that was leaked in an underground
hacking forum. BankBot is particularly risky because it disguises itself as legitimate banking apps,
typically using fake overlay screens to mimic existing banking apps and steal user credentials.
BankBot is also capable of hijacking and intercepting SMS messages, which means that it can
bypass SMS-based 2-factor authentication.

---

## 4. IoCs (威胁指标)

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `4D417C850C114F2791E839D47566500971668C41C47E290C8D7AEFADDC62F84C` | 恶意文件 |
| `6FD52E78902ED225647AFB87EB1E533412505B97A82EAA7CC9BA30BE6E658C0E` | 恶意文件 |
| `AE0C7562F50E640B81646B3553EB0A6381DAC66D015BAA0FA95E136D2DC855F7` | 恶意文件 |
| `CF46FDC278DC9D29C66E40352340717B841EAF447F4BEDDF33A2A21678B64138` | 恶意文件 |
| `DE2367C1DCD67C97FCF085C58C15B9A3311E61C122649A53DEF31FB689E1356F` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): overlay
4. **蠕虫传播** (HIGH): 发现
5. **权限滥用** (HIGH): 发现
