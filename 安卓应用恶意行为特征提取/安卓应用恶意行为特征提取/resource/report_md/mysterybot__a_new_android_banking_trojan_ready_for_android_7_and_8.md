# Sturnus: Mobile Banking Malware bypassing - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Sturnus: Mobile Banking Malware bypassing
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 即时通讯软件传播, 蓝牙/U盘传播
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
MysteryBot; a new
Android banking Trojan
ready for Android 7 and
8
01 June 2018
Intro Major Milestone:
Patent Granted for
Behavioural Analytics
While processing our daily set of suspicious samples, our detection rule for the Android banking trojan
LokiBot matched a sample that seemed quite different than LokiBot itself, urging us to take a closer look LEARN MORE
at it. Looking at t

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

function caught our attention, based on the naming convention in use, it seems that the function named
GetMail is meant to collect email messages from the infected device. The enhanced overlay attacks also
running on the latest Android versions combined with advanced keylogging and the potential under-
development features will allow MysteryBot to harvest a broad set of Personal Identifiable Information in
order to perform fraud.
In the last 6 months we observed that capabilities such as a proxy, keylogging, remote access (RAT), sound
recording and file uploading have become more and more common; we suspect this trend to only grow in

### 3.2 远程控制 (**CRITICAL**)

then paired to a specific key in such a way that it can register the keys that have been pressed which are
then saved for further use.
At the time of writing, the code for this the keylogger seems to still be under development as there is no
method yet to send the logs to the C2 server.
This code snippet shows the function used to record the keystrokes. Note that the y-coordinate for each
layer is set, whilst the x coordinate of each layer is multiplied by value of the current iteration (because
the layout of whole row of keys only differs on the x-axis). recordKeystrokes

realized that there is more going on: the name of the bot and the name of the panel changed to
“MysteryBot”, even the network communication changed.
During investigation of its network activity we found out that MysteryBot and LokiBot Android banker are
both running on the same C&C server. This quickly brought us to an early conclusion that this newly
discovered Malware is either an update to Lokibot, either another banking trojan developed by the same
actor.
To consolidate evidence, we searched some other sources and found more matches between samples of

Behavioural Analytics
While processing our daily set of suspicious samples, our detection rule for the Android banking trojan
LokiBot matched a sample that seemed quite different than LokiBot itself, urging us to take a closer look LEARN MORE
at it. Looking at the bot commands, we first thought that LokiBot had been improved. However, we quickly

[Page 2]
realized that there is more going on: the name of the bot and the name of the panel changed to

or credit card information at the moment the related app is opened by the victim. Mistiming the overlay
would make the overlay screen appear at an unexpected moment, resulting in the victim realizing
presence of the malware. This has been made difficult with the restrictions employed by Security-
Enhanced Linux (SELinux) and other security controls (sandbox restrictions) in Android 7 and 8. Hence,
actors have been working hard on finding new ways to time overlays correctly, which resulted in many
technical debates in the Android banking trojan criminal ecosystem.
A new technique has been conceived and is currently being used, it abuses the

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: app_replace, overlay

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

com.kutxabank.android Kutxabank
com.macif.mobile.application.android MACIF-Essentielpourmoi
com.microsoft.office.outlook MicrosoftOutlook
com.moneybookers.skrillpayments Skrill
com.moneybookers.skrillpayments.neteller NETELLER
com.ocito.cdn.activity.creditdunord CréditduNordpourMobile
com.paypal.android.p2pmobile PayPal

### 3.4 C2 反检测 (**HIGH**)

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS
CONTACT
RESEARCH

### 3.5 勒索软件 (**HIGH**)

MysteryBot linked to LokiBot on Koodous
Capabilities
This bot has most generic Android banking Trojan functionalities, but seems to be willing to surpass the
average. The overlay, key logging and ransomware functionalities are novel and are explained in detail in
the section here-after. All of the bot commands and respectful features are listed in the table below.
Calls a given phone number from the infected
CallToNumber

ZipParameters zipParameters = new ZipParameters();
zipParameters.setCompressionMethod(8);
zipParameters.setCompressionLevel(5);
zipParameters.setEncryptFiles(true);
zipParameters.setEncryptionMethod(99);
zipParameters.setAesKeyStrength(3);
zipParameters.setPassword(this.password);

### 3.6 广告欺诈 (**MEDIUM**)

the view is 0 by 0 pixels this should always be true, but if this somehow differs the keystroke is not
recorded.
public boolean onTouch(View view, MotionEvent motionEvent) {
view.performClick();
if (motionEvent.getAction() == 4) {
Keylogger.setKeyStroke(this.keylogger, Keylogger.getMotionEventFlagTotal(t
}

### 3.7 蠕虫传播 (**HIGH**)

financial institutions to asses whether or not they are target by the specific threats and that all infected
devices can be source of fraud and espionage.
IOC
Please note that MysteryBot is still under development at the time of writing and not widely spread.
Adobe Flash Player (install.apps)
334f1efd0b347d54a418d1724d51f8451b7d0bebbd05f648383d05c00726a7ae

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS
CONTACT
RESEARCH

com.csam.icici.bank.imobile iMobilebyICICIBank
com.ebay.gumtree.au Gumtree:Search,Buy&Sell
com.facebook.katana Facebook
com.facebook.orca Messenger–TextandVideoChatforFree
com.finansbank.mobile.cepsube QNBFinansbankCepŞubesi
com.fullsix.android.labanquepostale.accounta
LaBanquePostale

Forwards incoming calls of the device to anot
ForwardCall
her number
Shortened for GetAllSms, copies all the SMS
GetAlls
messages from the device
No code present, in development (probably st

### 3.8 权限滥用 (**HIGH**)

Android PACKAGE_USAGE_STATS permission (commonly named Usage Access permission). The code of
MysteryBot, has been consolidated with the so-called PACKAGE_USAGE_STATS technique. Because
abusing this Android permissions requires the victim to provide the permissions for usage, MysteryBot
employs the popular AccessibilityService, allowing the Trojan to enable and abuse any required
permission without the consent of the victim.
Experience has shown us that users often grant application Device
Administrator and AccessibilityService permissions, empowering the malware to perform further actions

MysteryBot linked to LokiBot on Koodous
Capabilities
This bot has most generic Android banking Trojan functionalities, but seems to be willing to surpass the
average. The overlay, key logging and ransomware functionalities are novel and are explained in detail in
the section here-after. All of the bot commands and respectful features are listed in the table below.
Calls a given phone number from the infected
CallToNumber

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `at.easybank.mbanking` | 域名类型 |
| `at.volksbank.volksbankmobile` | 域名类型 |
| `au.com.bankwest.mobile` | 域名类型 |
| `au.com.ingdirect.android` | 域名类型 |
| `au.com.nab.mobile` | 域名类型 |
| `au.com.suncorp.SuncorpBank` | 域名类型 |
| `com.advantage.RaiffeisenBank` | 域名类型 |
| `com.akbank.android.apps.akbank_direkt` | 域名类型 |
| `com.anz.android.gomoney` | 域名类型 |
| `com.aol.mobile.aolapp` | 域名类型 |
| `com.axis.mobile` | 域名类型 |
| `com.bankaustria.android.olb` | 域名类型 |
| `com.bankinter.launcher` | 域名类型 |
| `com.bbva.bbvacontigo` | 域名类型 |
| `com.bbva.netcash` | 域名类型 |
| `com.bendigobank.mobile` | 域名类型 |
| `com.boursorama.android.clients` | 域名类型 |
| `com.caisseepargne.android.mobilebanking` | 域名类型 |
| `com.chase.sig.android` | 域名类型 |
| `com.cibc.android.mobi` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `334f1efd0b347d54a418d1724d51f8451b7d0bebbd05f648383d05c00726a7ae` | 恶意文件 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @TargetApi | C2/通信 |
| @nking | C2/通信 |

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
| 传播性 | MEDIUM | 即时通讯软件传播, 蓝牙/U盘传播 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): app_replace, overlay
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
