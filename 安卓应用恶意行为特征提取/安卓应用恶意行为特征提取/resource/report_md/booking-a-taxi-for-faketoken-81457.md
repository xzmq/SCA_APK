# Booking a Taxi for Faketoken - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: VICTOR CHEBYSHEV
> **恶意软件名称**: Booking a Taxi for Faketoken
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Booking a Taxi for Faketoken
MALWARE DESCRIPTIONS 17 AUG 2017 3 minute read
// AUTHORS
VICTOR CHEBYSHEV
The Trojan-Banker.AndroidOS.Faketoken malware has been known about for already more than a
year. Throughout the time of its existence, it has worked its way up from a primitive Trojan
intercepting mTAN codes to an encrypter. The authors of its newer modifications continue to
upgrade the malware, while its geographical spread is growing. Some of these modifications
contain overlay mechanisms for about 2,000 financial apps. In one of the newest versions, we also
detected a mechanism f

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms

installed, the damage caused by Faketoken can be significant.
However, the following question may arise: what do fraudsters do in order to process a payment if
they have to enter an SMS code sent by the bank? Evildoers successfully accomplish this by
stealing incoming SMS messages and forwarding them to command-and-control servers.

[Page 7]
IN THE SAME CATEGORY

### 3.2 远程控制 (**CRITICAL**)

installed, the damage caused by Faketoken can be significant.
However, the following question may arise: what do fraudsters do in order to process a payment if
they have to enter an SMS code sent by the bank? Evildoers successfully accomplish this by
stealing incoming SMS messages and forwarding them to command-and-control servers.

[Page 7]
IN THE SAME CATEGORY

installed, the damage caused by Faketoken can be significant.
However, the following question may arise: what do fraudsters do in order to process a payment if
they have to enter an SMS code sent by the bank? Evildoers successfully accomplish this by
stealing incoming SMS messages and forwarding them to command-and-control servers.

[Page 7]
IN THE SAME CATEGORY

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

Mobile statistics
The code for recording a conversation
The authors of Faketoken.q kept the overlay features and simplified them considerably. So, the
Trojan is capable of overlaying several banking and miscellaneous applications, such as Android Pay,
Google Play Store, and apps for paying traffic tickets and booking flights, hotel rooms, and taxis.

[Page 6]

MALWARE DESCRIPTIONS 17 AUG 2017 3 minute read
// AUTHORS
VICTOR CHEBYSHEV
The Trojan-Banker.AndroidOS.Faketoken malware has been known about for already more than a
year. Throughout the time of its existence, it has worked its way up from a primitive Trojan
intercepting mTAN codes to an encrypter. The authors of its newer modifications continue to
upgrade the malware, while its geographical spread is growing. Some of these modifications

happens instantaneously, and the colors of the fake UI correspond to those of the original
launched app.
It should be noted that all of the apps attacked by this malware sample have support for linking
bank cards in order to make payments. However, the terms of some apps make it mandatory to link
a bank card in order to use the service. As millions of Android users have these applications
installed, the damage caused by Faketoken can be significant.
However, the following question may arise: what do fraudsters do in order to process a payment if

### 3.4 C2 反检测 (**HIGH**)

VICTOR CHEBYSHEV
The Trojan-Banker.AndroidOS.Faketoken malware has been known about for already more than a
year. Throughout the time of its existence, it has worked its way up from a primitive Trojan
intercepting mTAN codes to an encrypter. The authors of its newer modifications continue to
upgrade the malware, while its geographical spread is growing. Some of these modifications
contain overlay mechanisms for about 2,000 financial apps. In one of the newest versions, we also
detected a mechanism for attacking apps for booking taxis and paying traffic tickets issued by the

### 3.5 勒索软件 (**HIGH**)

Analysis of Elpaco: a Mimic
overlays contain formatting artifacts, which make it easy for a victim to identify it as fake: variant
Ymir: new stealthy
ransomware in the wild
QSC: A multi-plugin
framework used by
CloudComputating group in

### 3.7 蠕虫传播 (**HIGH**)

The Trojan-Banker.AndroidOS.Faketoken malware has been known about for already more than a
year. Throughout the time of its existence, it has worked its way up from a primitive Trojan
intercepting mTAN codes to an encrypter. The authors of its newer modifications continue to
upgrade the malware, while its geographical spread is growing. Some of these modifications
contain overlay mechanisms for about 2,000 financial apps. In one of the newest versions, we also
detected a mechanism for attacking apps for booking taxis and paying traffic tickets issued by the
Main Directorate for Road Traffic Safety.

[Page 8]
The screen overlays for the UI of a taxi-booking app
As screen overlays are a documented feature widely used in a large number of apps (window
managers, messengers, etc.), protecting yourself against such fake overlays is quite complicated, a
fact that is exploited by evildoers.
To this day we still have not registered a large number of attacks with the Faketoken sample, and
we are inclined to believe that this is one of its test versions. According to the list of attacked

year. Throughout the time of its existence, it has worked its way up from a primitive Trojan
intercepting mTAN codes to an encrypter. The authors of its newer modifications continue to
upgrade the malware, while its geographical spread is growing. Some of these modifications
contain overlay mechanisms for about 2,000 financial apps. In one of the newest versions, we also
detected a mechanism for attacking apps for booking taxis and paying traffic tickets issued by the
Main Directorate for Road Traffic Safety.
Not so long ago, thanks to our colleagues from a large Russian bank, we detected a new Trojan

### 3.8 权限滥用 (**HIGH**)

year. Throughout the time of its existence, it has worked its way up from a primitive Trojan
intercepting mTAN codes to an encrypter. The authors of its newer modifications continue to
upgrade the malware, while its geographical spread is growing. Some of these modifications
contain overlay mechanisms for about 2,000 financial apps. In one of the newest versions, we also
detected a mechanism for attacking apps for booking taxis and paying traffic tickets issued by the
Main Directorate for Road Traffic Safety.
Not so long ago, thanks to our colleagues from a large Russian bank, we detected a new Trojan

KSENIYA KUDASHEVA FABIO ASSOLINI
// REPORTS
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
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
8. 其他行为见详细信息...
