# Gugi: from an SMS Trojan to a Mobile-Banking Trojan - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: ROMAN UNUCHEK
> **恶意软件名称**: Gugi: from an SMS Trojan to a Mobile-Banking Trojan
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
Gugi: from an SMS Trojan to a Mobile-Banking Trojan
MALWARE DESCRIPTIONS 12 SEP 2016 6 minute read
// AUTHORS
ROMAN UNUCHEK
In the previous article, we described the mechanisms used by Trojan-Banker.AndroidOS.Gugi.c to
bypass a number of new Android 6 security features. In this article, we review the entire Gugi
mobile-banking Trojan family in more detail.
The use of WebSocket by Gugi
The mobile-banking Trojan family, Trojan-Banker.AndroidOS.Gugi is interesting due to its use of the
WebSocket protocol to interact with its command-and-control servers. This protocol combines
the advanta

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account

From SMS Trojans to Mobile Banking
on the infected device.
Trojans
In addition, the Trojan steals all outgoing SMS messages. Evolution of the Trojan-
Banker.AndroidOS.Gugi
In the middle of January 2014, just a couple of weeks after discovering FakeInst.fn, a new version of
“Fanta”

### 3.2 远程控制 (**CRITICAL**)

0x8EB8170A6B0957ED4943DAF6BA5C0F0A
0x01BC8A2C84D1481042723F347056B1B3 Download a banker to track
0xBF257FD4F46605A5DBE258561891D77B your parcel
0x01CD86238FE594CAC2495CE6BD38FAFA
0xCBCC996BF49FFE3F90B207103102177B
0x4C7C48B919C26278DD849ED4BB0B3192 Analysis of Elpaco: a Mimic
0x11F51C119BC1E7D2358E2565B2287925 variant

mobile-banking Trojan family in more detail.
The use of WebSocket by Gugi
The mobile-banking Trojan family, Trojan-Banker.AndroidOS.Gugi is interesting due to its use of the
WebSocket protocol to interact with its command-and-control servers. This protocol combines
the advantages of HTTP with those of commonly used sockets: there is no need to open extra

[Page 2]

mobile-banking Trojan family in more detail.
The use of WebSocket by Gugi
The mobile-banking Trojan family, Trojan-Banker.AndroidOS.Gugi is interesting due to its use of the
WebSocket protocol to interact with its command-and-control servers. This protocol combines
the advantages of HTTP with those of commonly used sockets: there is no need to open extra

[Page 2]

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: app_replace, phishing

[Page 1]
Gugi: from an SMS Trojan to a Mobile-Banking Trojan
MALWARE DESCRIPTIONS 12 SEP 2016 6 minute read
// AUTHORS
ROMAN UNUCHEK

[Page 1]
Gugi: from an SMS Trojan to a Mobile-Banking Trojan
MALWARE DESCRIPTIONS 12 SEP 2016 6 minute read
// AUTHORS
ROMAN UNUCHEK

### 3.4 C2 反检测 (**HIGH**)

to deliver MgBot what changed
Kaspersky GReAT experts analyze the Evasive Kaspersky expert describes new malicious tools
Panda APT’s infection chain, including shellcode employed by the Cloud Atlas APT, including
encrypted with DPAPI and RC5, as well as the implants of their signature backdoors
MgBot implant. VBShower, VBCloud, PowerShower, and
CloudAtlas.
THREATS CATEGORIES OTHER SECTIONS

### 3.5 勒索软件 (**HIGH**)

0xFA7C61CF2563F93DEA4BB9964D2E7806
0xC5A727E6C6A5E57EDDB16E6556D5D666
0xD644E6E68F83504787443E8C8A3CB47F Ymir: new stealthy
0xE778EAB7A2FB55C7BC67F15A692DE246 ransomware in the wild
0xE6C3329A8CC357C5BA455BB3C4372DE3
0x8BE9C3EDED33E2ADD22DE1A96C4A6B2B
QSC: A multi-plugin

### 3.6 广告欺诈 (**MEDIUM**)

The Trojan is actively transmitted via SMS spam, with a link to phishing web pages that show a
message indicating that the user has, supposedly, received an MMS picture.
Information about MMS message on phishing website
If the “show” button in the message is clicked, then the Trojan-Banker.AndroidOS.Gugi will be
downloaded onto the device. It is highly likely that the name of the Trojan downloaded from such a
websi фte will be similar to img09127639.jpg.apk.

### 3.7 蠕虫传播 (**HIGH**)

In late December 2015, we spotted the next version of Gugi, “Fanta v.1.1”. Its major difference from
the previous version was that the code had a way of disabling the phishing window (we would like to
remind you that Gugi can also be used as an SMS Trojan). Another new feature allowed contacts to
be added to the infected device at the request of the server. This version was spread much more
actively than the first one.
At the beginning of February 2016, we detected two new versions of Gugi, “Fanta v2.0” and “Fanta
v2.1”. These versions had an increased focus on banking. First, they came with a new phishing

[Page 1]
Gugi: from an SMS Trojan to a Mobile-Banking Trojan
MALWARE DESCRIPTIONS 12 SEP 2016 6 minute read
// AUTHORS
ROMAN UNUCHEK

### 3.8 权限滥用 (**HIGH**)

Leaking ads
did not let the Trojan function properly. In June, we found a new version of the Trojan, 2.0, in which
the malefactors had added support for Android 6. On Android 6 devices, the Trojan first requests
permission to draw over other apps. Then, using the permission to its own advantage, it practically
blocks the device, forcing the user to give Device Administrator rights to the malicious application
as well as permission to read and send SMS messages and make calls.
Pocket cryptofarms

[Page 10]
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
| `img09127639.jpg.apk` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): app_replace, phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
