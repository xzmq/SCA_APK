# The banker that encrypted files - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: ROMAN UNUCHEK
> **恶意软件名称**: The banker that encrypted files
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯, 泰国
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
The banker that encrypted files
MALWARE DESCRIPTIONS 19 DEC 2016 4 minute read
// AUTHORS
ROMAN UNUCHEK
Many mobile bankers can block a device in order to extort money from its user. But we have
discovered a modification of the mobile banking Trojan Trojan-Banker.AndroidOS.Faketoken that
went even further – it can encrypt user data. In addition to that, this modification is attacking more
than 2,000 financial apps around the world.
We have managed to detect several thousand Faketoken installation packages capable of
encrypting data, the earliest of which dates back to July 2016. Accor

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

g g
The Trojan is capable of interacting with protection mechanisms in the operating system. For
example, it requests rights to overlay other apps or the right to be a default SMS application. This
allows Faketoken to steal user data even in the latest versions of Android.
Once the Trojan becomes active, it requests administrator rights. If the user denies the request,
Faketoken repeatedly refreshes the window asking for these rights, which leaves the victim with
little choice.

### 3.2 远程控制 (**CRITICAL**)

Phishing page used by the Trojan to steal credit card details
Pocket cryptofarms
The Trojan can also get the list of applications for attack and an HTML template page to generate
phishing pages for the attacked applications from the C&C server. In our case, Faketoken received
a list of 2,249 financial applications from around the world.
Mobile malware evolution
2017

the address of the Gmail account and, even worse, reset the device to factory settings.

[Page 7]
What’s more, Faketoken can perform the following actions upon command from the C&C server:
Change masks to intercept incoming text messages;
Send text messages to a specified number with a specified text;
Send text messages with a specified text to a specified list of recipients;

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

// AUTHORS
ROMAN UNUCHEK
Many mobile bankers can block a device in order to extort money from its user. But we have
discovered a modification of the mobile banking Trojan Trojan-Banker.AndroidOS.Faketoken that
went even further – it can encrypt user data. In addition to that, this modification is attacking more
than 2,000 financial apps around the world.
We have managed to detect several thousand Faketoken installation packages capable of

[Page 1]
The banker that encrypted files
MALWARE DESCRIPTIONS 19 DEC 2016 4 minute read
// AUTHORS
ROMAN UNUCHEK

### 3.4 C2 反检测 (**HIGH**)

[Page 1]
The banker that encrypted files
MALWARE DESCRIPTIONS 19 DEC 2016 4 minute read
// AUTHORS
ROMAN UNUCHEK

### 3.5 勒索软件 (**HIGH**)

Table of Contents
Preparing the groundwork
Data theft
Ransomware banker
MD5

[Page 3]

Open a specified link in its own window;
Run an application;
Block the device in order to extort money for unblocking it. This command may include an
option indicating the need to encrypt files.
Ransomware banker
As mentioned above, the ransomware functionality in mobile banking Trojans is now commonplace,
after being pioneered by Svpeng in early 2014. However, the new Faketoken version can not only

### 3.6 广告欺诈 (**MEDIUM**)

[Page 5]
Examples of phishing messages displayed by the Trojan
If the user clicks on the message, the Trojan opens a phishing page designed to steal passwords
from Gmail accounts. In addition to that, the Trojan overlays the original Gmail application with this
page for the same purpose – to steal the password.
Phishing page imitating the login page of the Gmail mail service

### 3.7 蠕虫传播 (**HIGH**)

Trojan doesn’t like that, and will start requesting the right again.
Manipulations with application shortcuts can also be added to the preparatory stage. After
launching, Faketoken starts downloading an archive containing file icons of several applications (the
version being analyzed here has eight) related to social networks, instant messengers and
browsers. Then it tries to delete the previous shortcuts to these applications and create new ones.

[Page 4]

[Page 2]
g g
The Trojan is capable of interacting with protection mechanisms in the operating system. For
example, it requests rights to overlay other apps or the right to be a default SMS application. This
allows Faketoken to steal user data even in the latest versions of Android.
Once the Trojan becomes active, it requests administrator rights. If the user denies the request,

### 3.8 权限滥用 (**HIGH**)

[Page 2]
g g
The Trojan is capable of interacting with protection mechanisms in the operating system. For
example, it requests rights to overlay other apps or the right to be a default SMS application. This
allows Faketoken to steal user data even in the latest versions of Android.
Once the Trojan becomes active, it requests administrator rights. If the user denies the request,
Faketoken repeatedly refreshes the window asking for these rights, which leaves the victim with

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
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
