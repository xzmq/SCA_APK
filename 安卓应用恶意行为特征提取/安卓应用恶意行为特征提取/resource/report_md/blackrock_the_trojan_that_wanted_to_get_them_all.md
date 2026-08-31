# Sturnus: Mobile Banking Malware bypassing - 分析报告

> **来源**: McAfee
> **发布日期**: since 2014
> **作者**: of the Trojan got banned from undergroun
> **恶意软件名称**: Sturnus: Mobile Banking Malware bypassing
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 欧洲, 土耳其
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 社交媒体传播, 蓝牙/U盘传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS
CONTACT
RESEARCH
BlackRock - the Trojan
that wanted to get them
all
01 July 2020
Intro
Major Milestone:
Patent Granted for
Around May 2020 ThreatFabric analysts have uncovered a new strain of banking malware dubbed Behavioural Analytics
BlackRock that looked pretty familiar. After investigation, it became clear that this newcomer is derived
from the code of the Xerxes banking malware, which itself 

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account, device_info

the author of the Trojan got banned from underground forums, the source code of the Trojan was leaked.
During first half of 2018 MysteryBot was observed to be active. Although it was based on LokiBot it
contained upgrades in order to work properly on newer Android versions and used new techniques to
steal personal information. In the second half of 2018, Parasite appeared on the threat landscape as direct
successor of MysteryBot. It was enhanced with accessibility features and some automated scripts (such as

[Page 3]

Kaspersky, McAfee, Avira, and even applications to clean Android devices, such as TotalCommander, SD
Maid or Superb Cleaner. By doing so, the Trojan tries to avoid letting the victim remove it from the device
and establish some form of persistency.
BlackRock embeds following set of features, allowing it to remain under the radar and successfully harvest
personal information:
Overlaying: Dynamic (Local injects obtained from C2)
Keylogging

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: js_bridge, webview

Once the user grants the requested Accessibility Service privilege, BlackRock starts by granting itself
additional permissions. Those additional permissions are required for the bot to fully function without
having to interact any further with the victim. When done, the bot is functional and ready to receive
commands from the C2 server and perform the overlay attacks.
Commands
The commands supported by the actual version of the bot are listed below. It gives a good overview of
what the actor(s) can do on the infected device.

Once the user grants the requested Accessibility Service privilege, BlackRock starts by granting itself
additional permissions. Those additional permissions are required for the bot to fully function without
having to interact any further with the victim. When done, the bot is functional and ready to receive
commands from the C2 server and perform the overlay attacks.
Commands
The commands supported by the actual version of the bot are listed below. It gives a good overview of
what the actor(s) can do on the infected device.

[Page 7]
Profiling
One functionality that is so far unique to BlackRock is that it makes usage of the Android work profiles.
This Android feature is usually used by companies to define a device policy controller (DPC) in order to
control and apply policies on their mobile fleet. It allows to control various aspects of a device without per
se having complete administration rights on all aspects of the device.
BlackRock abuses this feature to gain admin privileges. It simply creates and attributes itself a profile

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS

PayPal Mobile Cash: Send and Request Mone
com.paypal.android.p2pmobile
y Fast
Payoneer – Global Payments Platform for Bus
com.payoneer.android
inesses
NETELLER - fast, secure and global money tra

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter, forum, domain_gen

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS
CONTACT
RESEARCH

### 3.6 广告欺诈 (**MEDIUM**)

BHIM UPI, Money Transfer, Recharge & Bill Pay
com.mobikwik_new
ment
Odeabank com.magiclick.odeabank
YouApp com.lynxspa.bancopopolare
Intesa Sanpaolo Mobile com.latuabancaperandroid
Kuveyt Türk com.kuveytturk.mobil

### 3.7 蠕虫传播 (**HIGH**)

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS
CONTACT
RESEARCH

Credit Card theft target list
The actual BlacRock target list used for credit card theft contains 111 applications:
App name Package name
Telegram org.telegram.messenger
Viber Messenger - Messages, Group Chats & C
com.viber.voip
alls

The commands supported by the actual version of the bot are listed below. It gives a good overview of
what the actor(s) can do on the infected device.
Command Description
Send_SMS Sends an SMS

[Page 5]
Command Description

### 3.8 权限滥用 (**HIGH**)

During first half of 2018 MysteryBot was observed to be active. Although it was based on LokiBot it
contained upgrades in order to work properly on newer Android versions and used new techniques to
steal personal information. In the second half of 2018, Parasite appeared on the threat landscape as direct
successor of MysteryBot. It was enhanced with accessibility features and some automated scripts (such as

[Page 3]
PayPal automated transfer scripts). In May 2019 the Xerxes Trojan first appeared, it was based on Parasite

Once the user grants the requested Accessibility Service privilege, BlackRock starts by granting itself
additional permissions. Those additional permissions are required for the bot to fully function without
having to interact any further with the victim. When done, the bot is functional and ready to receive
commands from the C2 server and perform the overlay attacks.
Commands
The commands supported by the actual version of the bot are listed below. It gives a good overview of
what the actor(s) can do on the infected device.

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `alior.bankingapp.android` | 域名类型 |
| `android.app.action.PROVISION` | 域名类型 |
| `android.app.extra` | 域名类型 |
| `android.app.extra.PROVISIONING` | 域名类型 |
| `ankingcom.usaa.mobile.android.usaa` | 域名类型 |
| `app.wizink.es` | 域名类型 |
| `au.com.ingdirect.android` | 域名类型 |
| `au.com.nab.mobile` | 域名类型 |
| `biz.mobinex.android.apps.cep_sifrematik` | 域名类型 |
| `cc.bitbank.bitbank` | 域名类型 |
| `ch.autoscout24.autoscout24` | 域名类型 |
| `clientapp.swiftcom.org` | 域名类型 |
| `co.edgesecure.app` | 域名类型 |
| `com.aadhk.woinvoice` | 域名类型 |
| `com.abanca.bancaempresas` | 域名类型 |
| `com.abnamro.nl.mobile.payments` | 域名类型 |
| `com.aff.otpdirekt` | 域名类型 |
| `com.akbank.android.apps.akbank_direkt` | 域名类型 |
| `com.akbank.softotp` | 域名类型 |
| `com.aleskovacic.messenger` | 域名类型 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 社交媒体传播, 蓝牙/U盘传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): js_bridge, webview
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): twitter, forum, domain_gen
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
