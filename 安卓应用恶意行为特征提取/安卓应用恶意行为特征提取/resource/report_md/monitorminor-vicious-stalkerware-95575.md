# MonitorMinor: vicious stalkerware? - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: VICTOR CHEBYSHEV
> **恶意软件名称**: MonitorMinor: vicious stalkerware?
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
MonitorMinor: vicious stalkerware?
RESEARCH 16 MAR 2020 5 minute read
// AUTHORS
VICTOR CHEBYSHEV
This app can track Gmail, WhatsApp, Instagram, and
Facebook user activity. What comes next? Telegram
and Threema?
Updated March 17th, 2020
The other day, our Android traps ensnared an interesting specimen of commercial software that is
positioned as a parental control app, but may also be used to secretly monitor family members or
colleagues – or, in other words, for stalking. Such apps are often called stalkerware. On closer
inspection, we found that this app outstrips all existing softw

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account, clipboard

KSENIYA KUDASHEVA FABIO ASSOLINI
// REPORTS
HoneyMyte updates CoolClient and The HoneyMyte APT evolves with a kernel-
deploys multiple stealers in recent mode rootkit and a ToneShell backdoor
campaigns
Kaspersky discloses a 2025 HoneyMyte (aka
Kaspersky researchers analyze updated

steps to provide information about the potential consequences of unlawful usage of the app.
On the other hand, we can’t see how this information can help potential targets of stalkers that
would decide to use this app. It is very intrusive and is able to exist on the target’s device without
being visible to its owner, and it can silently harvest practically every bit of the target’s personal IN THE SAME CATEGORY
communications. Due to the powerful characteristics of this app, we decided to draw attention to
it and inform those who defend people from stalkerware of the potential threat it poses. This is not
Yet another DCOM object for

### 3.2 远程控制 (**CRITICAL**)

reach is not limited to social networks and messengers: everything entered by the victim is
automatically sent to the MonitorMinor servers. The app also monitors the clipboard and forwards
the contents. The app also allows its owner to:
Control the device using SMS commands
View real-time video from the device’s cameras
Record sound from the device’s microphone
View browsing history in Chrome

and Threema?
Updated March 17th, 2020
The other day, our Android traps ensnared an interesting specimen of commercial software that is
positioned as a parental control app, but may also be used to secretly monitor family members or
colleagues – or, in other words, for stalking. Such apps are often called stalkerware. On closer
inspection, we found that this app outstrips all existing software of its class in terms of
functionality. Let’s take a look one step at a time.

### 3.4 C2 反检测 (**HIGH**)

to deliver MgBot what changed
Kaspersky GReAT experts analyze the Evasive Kaspersky expert describes new malicious tools
Panda APT’s infection chain, including shellcode employed by the Cloud Atlas APT, including
encrypted with DPAPI and RC5, as well as the implants of their signature backdoors
MgBot implant. VBShower, VBCloud, PowerShower, and
CloudAtlas.
THREATS CATEGORIES OTHER SECTIONS

### 3.7 蠕虫传播 (**HIGH**)

Non-mobile statistics
IT threat evolution Q3 2020
Mobile statistics
Propagation
According to KSN statistics, India currently has the largest share of installations of this application
(14.71%). In addition, a Gmail account with an Indian name is stitched into the body of MonitorMinor,

RESEARCH 16 MAR 2020 5 minute read
// AUTHORS
VICTOR CHEBYSHEV
This app can track Gmail, WhatsApp, Instagram, and
Facebook user activity. What comes next? Telegram
and Threema?
Updated March 17th, 2020

intercept SMS and call data (spyware that’s able to log them is much less common) are added to
the geolocation transmission.
But today, SMS are used mainly for receiving one-time passwords and not much else — their niche
has been captured almost entirely by messengers, which these days even facilitate business
negotiations. Moreover, they claim to be an alternative to “traditional” voice communication. So any
software with tracking/spying functionality worth its salt must be able to intercept data from
messengers. The sample we found (assigned the verdict Monitor.AndroidOS.MonitorMinor.c) is a

to display coordinates, and they only contain a few lines of code.
Often, their creators use geofencing technology, whereby a notification about the victim’s
movements is sent only if they go beyond (or enter) a particular area. In some cases, functions to
intercept SMS and call data (spyware that’s able to log them is much less common) are added to
the geolocation transmission.
But today, SMS are used mainly for receiving one-time passwords and not much else — their niche
has been captured almost entirely by messengers, which these days even facilitate business

### 3.8 权限滥用 (**HIGH**)

[Page 4]
Android is a very user-friendly operating system. It is especially friendly to users with disabilities:
with the Accessibility Services API, the phone can read aloud incoming messages and any other
text in app windows. What’s more, with the help of Accessibility Services, it is possible to obtain in
real time the structure of the app window currently displayed on the smartphone screen: input
fields, buttons, their names, etc.

JOHN HULTQUIST,BRIAN BARTHOLOMEW,SUGURU ISHIMARU,
VITALY KAMLUK,SEONGSU PARK,YUSUKE NIWA,
MOTOHIKO SATO
The situation changes if a SuperUser-type app (SU utility) is installed, which grants root access to
the system. Exactly how they get on the device — installed at the factory, by a user, or even by 17 JUN 2020, 1:00PM
GReAT Ideas. Powered by SAS:
malware — is not so important. The main point is that they cause one of the system’s key security

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): 发现
3. **C2 反检测** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
5. **权限滥用** (HIGH): 发现
