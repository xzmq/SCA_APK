# INCIDENTS 12 DEC 2017 3 minute read - 分析报告

> **来源**: Securelist
> **发布日期**: 未知
> **作者**: ROMAN UNUCHEK
> **恶意软件名称**: INCIDENTS 12 DEC 2017 3 minute read
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
Still Stealing
INCIDENTS 12 DEC 2017 3 minute read
// AUTHORS
ROMAN UNUCHEK
Two years ago in October 2015 we published a blogpost about a popular malware that was being
distributed from the Google Play Store. Over the next two years we detected several similar apps
on Google Play, but in October and November 2017 we found 85 new malicious apps on Google Play
that are stealing credentials for VK.com. All of them have been detected by Kaspersky Lab
products as Trojan-PSW.AndroidOS.MyVk.o. We reported 72 of them to Google and they deleted
these malicious apps from Google Play Store, 13 o

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: account

[Page 1]
Still Stealing
INCIDENTS 12 DEC 2017 3 minute read
// AUTHORS
ROMAN UNUCHEK

### 3.2 远程控制 (**CRITICAL**)

source Telegram SDK and work almost like every other such app. Except one thing – they added
users to promoted groups/chats. These apps receive a list with groups/chats from their server.
What’s more, they can add users to groups anytime – to do so they steal a GCM token which
allows cybercriminals to send commands 24/7.
We also discovered an interesting thing about the malicious website extensionsapiversion.space.
According to KSN statistics, in some cases it was used for mining cryptocurrencies by using an API
from http://coinhive.com.

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

com.appoffline.musicplayer 6974770565C5F0FFDD52FC74F1BCA732
com.planeplane.paperplane 6CBC63CBE753B2E4CB6B9A8505775389
Deep analysis of the flaw in
BetterBank reward logic
SOCIAL NETWORKS GOOGLE ANDROID MALWARE DESCRIPTIONS
Post-exploitation framework
now also delivered via npm

### 3.4 C2 反检测 (**HIGH**)

FROM THE SAME AUTHORS
Malicious code where a Trojan executes JS code to get VK credentials.
I know where your pet is
Then the credentials are encrypted and uploaded to the malicious website.
Leaking ads
Pocket cryptofarms
Mobile malware evolution

### 3.7 蠕虫传播 (**HIGH**)

now also delivered via npm
Still Stealing
Your email address will not be published. Required fields are marked * Massive npm infection: the
Shai-Hulud worm and patient
zero
Type your comment here
The SOC files: Rumble in the

### 3.8 权限滥用 (**HIGH**)

KSENIYA KUDASHEVA FABIO ASSOLINI
// REPORTS
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
| `com.anocat.stelth` | 域名类型 |
| `com.appoffline.musicplayer` | 域名类型 |
| `com.junglebeat.musicplayer.offmus` | 域名类型 |
| `com.musicould.close` | 域名类型 |
| `com.parmrp.rump` | 域名类型 |
| `com.planeplane.paperplane` | 域名类型 |
| `com.prostie.dvijenija` | 域名类型 |
| `com.sharp.playerru` | 域名类型 |
| `com.weeclient.clientold` | 域名类型 |
| `com.xclient.old` | 域名类型 |
| `com.yourmusicoff.yourmusickoff` | 域名类型 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `http://coinhive.com` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到6类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): 发现
5. **蠕虫传播** (HIGH): 发现
7. 其他行为见详细信息...
