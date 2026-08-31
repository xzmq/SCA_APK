# Ghimob: a Tétrade threat actor moves to infect mobile devices - 分析报告

> **来源**: 未知
> **发布日期**: Sep 24
2020
> **作者**: GREAT
> **恶意软件名称**: Ghimob: a Tétrade threat actor moves to infect mobile devices
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯, 巴西
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Ghimob: a Tétrade threat actor moves to infect mobile devices
MALWARE DESCRIPTIONS 09 NOV 2020 6 minute read
// AUTHORS
GREAT
Guildma, a threat actor that is part of the Tétrade family of banking trojans, has been working on
bringing in new techniques, creating new malware and targeting new victims. Recently, their new
creation, the Ghimob banking trojan, has been a move toward infecting mobile devices, targeting
financial apps from banks, fintechs, exchanges and cryptocurrencies in Brazil, Paraguay, Peru,
Portugal, Germany, Angola and Mozambique.
Ghimob is a full-fledged spy in your 

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: contacts, account

This is likely due to low Internet speeds in Brazil: sending text information from time to time
consumes less bandwidth than sending a screen recording in real time, thus increasing the chances
of successful fraud for the cybercriminal. While BRATA uses an overlay with a fake WebView to
steal credentials, Ghimob does not need to do that, as it reads the fields directly from the target
app through accessibility features. The following words in Portuguese are monitored: saldo
(balance), investimento (investment), empréstimo (lending), extrato (statement).
Conclusions

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: webview, config_update

the transaction, they can insert a black screen as an overlay or open some website in full screen, so
while the user looks at that screen, the criminal performs the transaction in the background by
using the financial app running on the victim’s smartphone that the user has opened or logged in to.
From a technical standpoint, Ghimob is also interesting in that it uses C2s with fallback protected
by Cloudflare, hides its real C2 with DGA and employs several other tricks, posing as a strong
competitor in this field. But yet, no sign of MaaS (malware-as-a-service). Compared to BRATA or
Basbanke, another mobile banking trojan family originating in Brazil, Ghimob is far more advanced

Control Panel used by Ghimob for listing infected victims
Instead of recording the user screen via the MediaProjection API, like BRATA does, Ghimob sends
accessibility-related information from the current active window, as can be seen below from the
output of the “301” command returned from the C2. All the commands used by the RAT are
described in our private report for customers of our Financial Threat Intel Portal.
Client:[TARGETED APP]
ID: xDROID_smg930a7.1.125_7206eee5b3775586310270_3.1

The APKs thus distributed are posing as installers of popular apps; they are not on Google Play but GReAT Ideas. Green Tea Edition
rather hosted in several malicious domains registered by Guildma operators. Once installed on the JOHN HULTQUIST,BRIAN BARTHOLOMEW,SUGURU ISHIMARU,
phone, the app will abuse Accessibility Mode to gain persistence, disable manual uninstallation and VITALY KAMLUK,SEONGSU PARK,YUSUKE NIWA,
allow the banking trojan to capture data, manipulate screen content and provide full remote control MOTOHIKO SATO
to the fraudster: a very typical mobile RAT.
17 JUN 2020, 1:00PM
GReAT Ideas. Powered by SAS:

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

MALWARE DESCRIPTIONS 09 NOV 2020 6 minute read
// AUTHORS
GREAT
Guildma, a threat actor that is part of the Tétrade family of banking trojans, has been working on
bringing in new techniques, creating new malware and targeting new victims. Recently, their new
creation, the Ghimob banking trojan, has been a move toward infecting mobile devices, targeting
financial apps from banks, fintechs, exchanges and cryptocurrencies in Brazil, Paraguay, Peru,

MALWARE DESCRIPTIONS 09 NOV 2020 6 minute read
// AUTHORS
GREAT
Guildma, a threat actor that is part of the Tétrade family of banking trojans, has been working on
bringing in new techniques, creating new malware and targeting new victims. Recently, their new
creation, the Ghimob banking trojan, has been a move toward infecting mobile devices, targeting
financial apps from banks, fintechs, exchanges and cryptocurrencies in Brazil, Paraguay, Peru,

malware, it is possible to see all the apps monitored and targeted by the RAT. These are mainly
institutions in Brazil (where it watches 112 apps), but since Ghimob, like other Tétrade threat actors,
has been moving toward expanding its operations, it also watches the system for cryptocurrency
apps from different countries (thirteen apps) and international payment systems (nine apps). Also
targeted are banks in Germany (five apps), Portugal (three apps), Perú (two apps), Paraguay (two
apps), Angola and Mozambique (one app per country). FROM THE SAME AUTHORS
The malware also blocks the user from uninstalling it, restarting or shutting down the device. This is APT annual review: What the

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: domain_gen

As soon as the malware is launched, it tries to detect common emulators, checks for the presence
of a debugger attached to the process and the manifest file, and also checks for a debuggable
flag. If any of these are present, then the malware simply terminates itself. Newer versions of the
malware have moved the emulator names to an encrypted configuration file. If those previous

[Page 4]
checks are passed, the user is then presented with the default Android accessibility window, as the

### 3.5 勒索软件 (**HIGH**)

3aa0cb27d4cbada2effb525f2ee0e61e
3e6c5e42c0e06e6eaa03d3d890651619
Ymir: new stealthy
4a7e75a8196622b340bedcfeefb34fff ransomware in the wild
4b3743373a10dad3c14ef107f80487c0
4f2cebc432ec0c4cf2f7c63357ef5a16
QSC: A multi-plugin

### 3.6 广告欺诈 (**MEDIUM**)

While monitoring a Guildma Windows malware campaign, we were able to find malicious URLs used 13 MAY 2021, 1:00PM
GReAT Ideas. Balalaika Edition
for distributing both ZIP files for Windows boxes and APK files, all from the same URL. If the user-
agent that clicked the malicious link is an Android-based browser, the file downloaded will be the BORIS LARIN,DENIS LEGEZO
Ghimob APK installer.
26 FEB 2021, 12:00PM
The APKs thus distributed are posing as installers of popular apps; they are not on Google Play but GReAT Ideas. Green Tea Edition

### 3.7 蠕虫传播 (**HIGH**)

Ghimob detections: Brazil for now, but ready to expand abroad
To lure the victim into installing the malicious file, the email is written as if from a creditor and
provides a link where the recipient could view more information, while the app itself pretends to be
Google Defender, Google Docs, WhatsApp Updater, etc.
A malicious message distributing the malware, written in Brazilian Portuguese
A persistent RAT in your pocket
As soon as the malware is launched, it tries to detect common emulators, checks for the presence

### 3.8 权限滥用 (**HIGH**)

26 FEB 2021, 12:00PM
The APKs thus distributed are posing as installers of popular apps; they are not on Google Play but GReAT Ideas. Green Tea Edition
rather hosted in several malicious domains registered by Guildma operators. Once installed on the JOHN HULTQUIST,BRIAN BARTHOLOMEW,SUGURU ISHIMARU,
phone, the app will abuse Accessibility Mode to gain persistence, disable manual uninstallation and VITALY KAMLUK,SEONGSU PARK,YUSUKE NIWA,
allow the banking trojan to capture data, manipulate screen content and provide full remote control MOTOHIKO SATO
to the fraudster: a very typical mobile RAT.
17 JUN 2020, 1:00PM

able to record it and later replay it to unlock the device. When the cybercriminal is ready to perform

[Page 2]
the transaction, they can insert a black screen as an overlay or open some website in full screen, so
while the user looks at that screen, the criminal performs the transaction in the background by
using the financial app running on the victim’s smartphone that the user has opened or logged in to.
From a technical standpoint, Ghimob is also interesting in that it uses C2s with fallback protected

[Page 9]
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
| `android.widget.EditText` | 域名类型 |
| `android.widget.FrameLayout` | 域名类型 |
| `android.widget.LinearLayout` | 域名类型 |
| `com.android.launcher3` | 域名类型 |
| `com.sysdroidxx.addons` | 域名类型 |
| `www.realcc.com` | 域名类型 |

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
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): contacts, account
2. **远程控制** (CRITICAL): webview, config_update
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): domain_gen
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
