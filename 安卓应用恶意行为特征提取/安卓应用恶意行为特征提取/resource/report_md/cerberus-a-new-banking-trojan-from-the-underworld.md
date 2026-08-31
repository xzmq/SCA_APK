# Sturnus: Mobile Banking Malware bypassing - 分析报告

> **来源**: ThreatFabric
> **发布日期**: 未知
> **作者**: claim that it was used for private opera
> **恶意软件名称**: Sturnus: Mobile Banking Malware bypassing
> **厂商检测名**: `com.imo.android.imoim`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 日本
| 活动时间 | 未知
| 传播方式 | 钓鱼, 即时通讯软件传播, 蓝牙/U盘传播
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
Cerberus - A new
banking Trojan from the
underworld
01 August 2019
Intro
Major Milestone:
Patent Granted for
In June 2019, ThreatFabric analysts found a new Android malware, dubbed “Cerberus”, being rented out onBehavioural Analytics
underground forums. Its authors claim that it was used for private operations for two years preceding the
start of the rental. They also state that th

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account, device_info

...
}
Targets
Some examples of phishing overlays are shown below. They exist in two types: the credentials stealers
(first 2 screenshots) and the credit card grabbers (last screenshot).
 
The only active target list observed in the wild is available in the appendix and contains a total of 30

updateModule Updates the payload module
Cerberus features
Cerberus malware has the same capabilities as most other Android banking Trojans such as the use of
overlay attacks, SMS control and contact list harvesting. The Trojan can also leverage keylogging to
broaden the attack scope. Overall, Cerberus has a pretty common feature list and although the malware
seems to have been written from scratch there does not seem to be any innovative functionality at this
time. For example, some of the more advanced banking Trojans now offer features such as a back-connect

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: webview, config_update

was also huge increase in the number of Anubis samples found in the wild, but the new actors using
Anubis have no support or updates.
Due to this Cerberus will come in handy for actors that want to focus on performing fraud without having
to develop and maintain a botnet and C2 infrastructure.
Analysis of evasion techniques
Along with the standard payload and string obfuscation, Cerberus uses a rather interesting technique to
prevent analysis of the Trojan.

permissions, such as permissions needed to send messages and make calls, without requiring any user
interaction. It also disables Play Protect (Google’s preinstalled antivirus solution) to prevent its discovery
and deletion in the future. After conveniently granting itself additional privileges and securing its
persistence on the device, Cerberus registers the infected device in the botnet and waits for commands
from the C2 server while also being ready to perform overlay attacks.
The commands supported by the analyzed version of the Cerberus bot are listed below. As can be seen,
the possibilities offered by the bot are pretty common.

updateModule Updates the payload module
Cerberus features
Cerberus malware has the same capabilities as most other Android banking Trojans such as the use of
overlay attacks, SMS control and contact list harvesting. The Trojan can also leverage keylogging to
broaden the attack scope. Overall, Cerberus has a pretty common feature list and although the malware
seems to have been written from scratch there does not seem to be any innovative functionality at this
time. For example, some of the more advanced banking Trojans now offer features such as a back-connect

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

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter, forum

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS
CONTACT
RESEARCH

### 3.6 广告欺诈 (**MEDIUM**)

The commands supported by the analyzed version of the Cerberus bot are listed below. As can be seen,
the possibilities offered by the bot are pretty common.
Command Description
Shows a push notification. Clicking on thenoti
push fication will result in launching a specified ap
p
startApp Starts the specified application

### 3.7 蠕虫传播 (**HIGH**)

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS
CONTACT
RESEARCH

jp.co.rakuten_bank.rakutenbank -
mobi.societegenerale.mobile.lappli L’Appli Société Générale
net.bnpparibas.mescomptes Mes Comptes BNP Paribas
org.telegram.messenger Telegram
Questions or demo?

[Page 15]

forwardCall
er
Sends a text message with specified text from
sendSms the infecteddevice to the specified phone nu
mber
Triggers the overlay attack against the specifi
startInject

### 3.8 权限滥用 (**HIGH**)

}
How it works
When the malware is first started on the device it will begin by hiding its icon from the application drawer.
Then it will ask for the accessibility service privilege as visible in the following screenshot:

[Page 6]

interaction. It also disables Play Protect (Google’s preinstalled antivirus solution) to prevent its discovery
and deletion in the future. After conveniently granting itself additional privileges and securing its
persistence on the device, Cerberus registers the infected device in the botnet and waits for commands
from the C2 server while also being ready to perform overlay attacks.
The commands supported by the analyzed version of the Cerberus bot are listed below. As can be seen,
the possibilities offered by the bot are pretty common.
Command Description

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.android.vending` | 域名类型 |
| `com.boursorama.android.clients` | 域名类型 |
| `com.caisseepargne.android.mobilebanking` | 域名类型 |
| `com.chase.sig.android` | 域名类型 |
| `com.clairmail.fth` | 域名类型 |
| `com.connectivityapps.hotmail` | 域名类型 |
| `com.google.android.gm` | 域名类型 |
| `com.gzhlubw.pmevdiexmn` | 域名类型 |
| `com.hvdnaiujzwo.fovzeukzy` | 域名类型 |
| `com.imo.android.imoim` | 域名类型 |
| `com.infonow.bofa` | 域名类型 |
| `com.instagram.android` | 域名类型 |
| `com.konylabs.capitalone` | 域名类型 |
| `com.mail.mobile.android.mail` | 域名类型 |
| `com.microsoft.office.outlook` | 域名类型 |
| `com.mwmnfwt.arhkrgajn` | 域名类型 |
| `com.ognbsfhszj.hqpquokjdp` | 域名类型 |
| `com.snapchat.android` | 域名类型 |
| `com.tencent.mm` | 域名类型 |
| `com.twitter.android` | 域名类型 |

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
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 钓鱼, 即时通讯软件传播, 蓝牙/U盘传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): webview, config_update
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): twitter, forum
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
