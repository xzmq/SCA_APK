# APT-C-23 group evolves its Android - 分析报告

> **来源**: Trend Micro
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: APT-C-23 group evolves its Android
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
ESET Research
APT-C-23 group evolves its Android
spyware
ESET researchers uncover a new version of Android spyware used by the APT-C-23 threat
group against targets in the Middle East
Lukas Stefanko
30 Sep 2020 • 9 min. read
[Page 2]
We have discovered a previously unreported version of Android spyware used by APT-C-23, a threat
group also known as Two-tailed Scorpion and mainly targeting the Middle East. ESET products
detect the malware as Android/SpyC23.A.
The APT-C-23 group is known to have used both Windows and Android components in its
operations, with the Android components firs

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account, device_info

analyses of APT-C-23’s mobile malware were published.
Compared to the versions documented in 2017, Android/SpyC23.A has extended spying
functionality, including reading notifications from messaging apps, call recording and screen
recording, and new stealth features, such as dismissing notifications from built-in Android security
apps. One of the ways the spyware is distributed is via a fake Android app store, using well-known
apps as a lure.
Timeline and discovery

Take pictures
Record audio
Restart Wi-Fi
Exfiltrate call logs
Exfiltrate all SMS messages
Exfiltrate all contacts
Download files to device

### 3.2 远程控制 (**CRITICAL**)

[Page 2]
We have discovered a previously unreported version of Android spyware used by APT-C-23, a threat
group also known as Two-tailed Scorpion and mainly targeting the Middle East. ESET products
detect the malware as Android/SpyC23.A.
The APT-C-23 group is known to have used both Windows and Android components in its
operations, with the Android components first described in 2017. In the same year, multiple
analyses of APT-C-23’s mobile malware were published.

the victims end up with a functioning app they intended to download and spyware silently running
in the background. In some cases (e.g. WeMessage, AndroidUpdate) the downloaded apps did not
have any real functionality, and only served as bait for installing the spyware.
When first launched, the malware starts to communicate with its Command and Control (C&C)
server. It registers the new victim and sends the victim’s device information to the C&C.

[Page 10]

the victims end up with a functioning app they intended to download and spyware silently running
in the background. In some cases (e.g. WeMessage, AndroidUpdate) the downloaded apps did not
have any real functionality, and only served as bait for installing the spyware.
When first launched, the malware starts to communicate with its Command and Control (C&C)
server. It registers the new victim and sends the victim’s device information to the C&C.

[Page 10]

the victims end up with a functioning app they intended to download and spyware silently running
in the background. In some cases (e.g. WeMessage, AndroidUpdate) the downloaded apps did not
have any real functionality, and only served as bait for installing the spyware.
When first launched, the malware starts to communicate with its Command and Control (C&C)
server. It registers the new victim and sends the victim’s device information to the C&C.

[Page 10]

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

After installation, the malware requests a series of additional, sensitive permissions, using social
engineering-like techniques to fool technically inexperienced users. These additional permission
requests are disguised as security and privacy features:
Under the guise of “Messages Encryption”, the app requests permission to read the user’s notifications
Under the guise of “Private Messages”, the app requests permission to turn off Play Protect
Under the guise of “Private Video Chat”, the app requests permission to record the user’s screen
These steps are shown in the video below.

### 3.5 勒索软件 (**HIGH**)

[Page 12]
Figure 7. Returned strings from the native library
The encrypted string serves two purposes: the first part – before the hyphen (“-”) – is used as part
of the password to encrypt files extracted from the affected device. The second part is first decoded
(base64) and then decrypted (AES). The decrypted string might, for example, suggest a Facebook
profile page for the C&C, but it is still obfuscated.
Figure 8. Decrypted but still obfuscated URL

### 3.7 蠕虫传播 (**HIGH**)

Record screen and take screenshots

[Page 11]
Record incoming and outgoing calls in WhatsApp
Make a call while creating a black screen overlay activity (to hide call activity)
Read text of notifications from selected messaging and social media apps: WhatsApp, Facebook, Telegram,
Instagram, Skype, Messenger, Viber, imo Table of Contents

Record incoming and outgoing calls in WhatsApp
Make a call while creating a black screen overlay activity (to hide call activity)
Read text of notifications from selected messaging and social media apps: WhatsApp, Facebook, Telegram,
Instagram, Skype, Messenger, Viber, imo Table of Contents
•
Dismiss notifications from built-in security apps on some Android devices: Timeline and discovery
• Distribution

Installation and permissions
Before installation, Android/SpyC23.A requests a number of invasive permissions, including taking
pictures and videos, recording audio, reading and modifying contacts, and reading and sending
SMS.
After installation, the malware requests a series of additional, sensitive permissions, using social
engineering-like techniques to fool technically inexperienced users. These additional permission
requests are disguised as security and privacy features:

### 3.8 权限滥用 (**HIGH**)

[Page 11]
Record incoming and outgoing calls in WhatsApp
Make a call while creating a black screen overlay activity (to hide call activity)
Read text of notifications from selected messaging and social media apps: WhatsApp, Facebook, Telegram,
Instagram, Skype, Messenger, Viber, imo Table of Contents
•

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.miui.securitycenter` | 域名类型 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @eset | C2/通信 |
| @malwrhunterteam | C2/通信 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到6类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): 发现
3. **C2 反检测** (HIGH): twitter
4. **勒索软件** (HIGH): 发现
5. **蠕虫传播** (HIGH): 发现
7. 其他行为见详细信息...
