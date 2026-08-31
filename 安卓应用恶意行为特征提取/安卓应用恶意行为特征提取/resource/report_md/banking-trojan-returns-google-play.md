# BankBot trojan returns to Google Play - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: BankBot trojan returns to Google Play
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等)
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
ESET Research Mobile Security
BankBot trojan returns to Google Play
with new tricks
The Android banking trojan that we first informed about in the beginning of this year has
found its way to Google Play again and contains new tricks designed to get access to the
private banking information of the user.
Lukas Stefanko
25 Sep 2017 • 6 min. read
[Page 2]
[Page 3]
The dangerous Android banking trojan that we first reported here at the beginning of 2017 has
found its way to Google Play again, now stealthier than ever.
Subsequently dubbed BankBot, the banking trojan has been evolving throug

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

[Page 3]
The dangerous Android banking trojan that we first reported here at the beginning of 2017 has
found its way to Google Play again, now stealthier than ever.
Subsequently dubbed BankBot, the banking trojan has been evolving throughout the year,
resurfacing in different versions both on and outside Google Play. The variant we discovered on
Google Play on September 4 is the first one to successfully combine the recent steps of BankBot’s

obtain permission to draw over other apps
After these tasks are successfully carried out, the malware can start working towards its next goal:
stealing the victim’s credit card details. As opposed to other BankBot variants that target an
extensive list of specific banking applications and impersonate their login forms in order to harvest
entered credentials, this one focuses exclusively on Google Play – an app all Android users have

[Page 13]

### 3.2 远程控制 (**CRITICAL**)

trojans.
Analyzed sample / IoCs
Package name Hash
com.mygamejewelsclassic.app B556FB1282578FFACDBF2126480A7C221E610F2F
com.w8fjgwopjmv.ngfes.app 4D3E3E7A1747CF845D21EC5E9F20F399D491C724
Award-winning news, views, and insight from the ESET security community English
TIPS & ADVICE BUSINESS SECURITY ESET RESEARCH WeLiveScience FEATURED TOPICS ABOUT US

it requests. If an app asks for intrusive permissions – even more so if Accessibility-related – read them with
caution and only grant them if absolutely sure of the app’s reliability.
What is BankBot?
First detected by ESET on December 26 2016 and first analyzed by Dr.Web, BankBot is a remotely controlled Android
banking trojan capable of harvesting banking details using phony login forms for a number of apps, intercepting
text messages in order to bypass 2-factor-authentication, and displaying unsolicited push notifications.
Shortly after the discovery of the apps trojanized with BankBot on Google Play in the beginning of 2017, we have

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: overlay

ESET Research Mobile Security
BankBot trojan returns to Google Play
with new tricks
The Android banking trojan that we first informed about in the beginning of this year has
found its way to Google Play again and contains new tricks designed to get access to the
private banking information of the user.
Lukas Stefanko

[Page 1]
ESET Research Mobile Security
BankBot trojan returns to Google Play
with new tricks
The Android banking trojan that we first informed about in the beginning of this year has
found its way to Google Play again and contains new tricks designed to get access to the

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: forum

What makes it so dangerous?
In this campaign, the crooks have put together a set of techniques with rising popularity among
Android malware authors – abusing Android Accessibility Service, impersonating Google, and
setting a timer delaying the onset of malicious activity to evade Google’s security measures.

[Page 15]
The techniques combined make it very difficult for the victim to recognize the threat in time.

### 3.6 广告欺诈 (**MEDIUM**)

The infected device shows an alert prompting the user to enable something named “Google
Service” (note: the malicious alert appears independent of the user’s current activity, and with no
apparent connection to the game).
After clicking on OK, which is the only way to stop the alert from appearing, the user is taken to the
Android Accessibility menu, where services with accessibility functions are managed. Among
legitimate ones, a new service named “Google Service” is listed, created by the malware. Clicking on
it displays a description taken from Google’s original Terms of Service.

### 3.7 蠕虫传播 (**HIGH**)

cunning infection mechanism abusing Android’s Accessibility Service.
Misuse of Android Accessibility has been previously observed in a number of different trojans,
mostly outside Google Play. Recent analyses from SfyLabs and Zscaler have confirmed that the
crooks spreading BankBot managed to upload an app with the Accessibility-abusing functionality
to Google Play, only without the banking malware payload.
The “complete puzzle” featuring the banking malware payload that managed to sneak into Google
Play masqueraded as a game named Jewels Star Classic (it is important to note that the attackers

How to stay safe?
activate device administrator for BankBot
• What is BankBot?
set BankBot as default SMS messaging app
obtain permission to draw over other apps
After these tasks are successfully carried out, the malware can start working towards its next goal:
stealing the victim’s credit card details. As opposed to other BankBot variants that target an

### 3.8 权限滥用 (**HIGH**)

resurfacing in different versions both on and outside Google Play. The variant we discovered on
Google Play on September 4 is the first one to successfully combine the recent steps of BankBot’s
evolution: improved code obfuscation, a sophisticated payload dropping functionality, and a
cunning infection mechanism abusing Android’s Accessibility Service.
Misuse of Android Accessibility has been previously observed in a number of different trojans,
mostly outside Google Play. Recent analyses from SfyLabs and Zscaler have confirmed that the
crooks spreading BankBot managed to upload an app with the Accessibility-abusing functionality

[Page 13]
preinstalled on their devices.
When the user launches the Google Play app, BankBot steps in and overlays the legitimate app
with a fake form requesting user’s credit card details.(Fig. 7).

[Page 14]

activate device administrator for BankBot
• What is BankBot?
set BankBot as default SMS messaging app
obtain permission to draw over other apps
After these tasks are successfully carried out, the malware can start working towards its next goal:
stealing the victim’s credit card details. As opposed to other BankBot variants that target an
extensive list of specific banking applications and impersonate their login forms in order to harvest

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.mygamejewelsclassic.app` | 域名类型 |
| `com.w8fjgwopjmv.ngfes.app` | 域名类型 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等) |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): overlay
4. **C2 反检测** (HIGH): forum
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
