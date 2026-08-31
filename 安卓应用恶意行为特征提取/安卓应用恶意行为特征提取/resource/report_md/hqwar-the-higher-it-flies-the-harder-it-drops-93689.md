# HQWar: the higher it flies, the harder it drops - 分析报告

> **来源**: Securelist
> **发布日期**: 未知
> **作者**: VICTOR CHEBYSHEV
> **恶意软件名称**: HQWar: the higher it flies, the harder it drops
> **厂商检测名**: `android.hqwar.gen50116`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 韩国, 俄罗斯
| 活动时间 | 未知
| 传播方式 | 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
HQWar: the higher it flies, the harder it drops
MALWARE DESCRIPTIONS 02 OCT 2019 4 minute read
// AUTHORS
VICTOR CHEBYSHEV
Mobile dropper Trojans are one of today’s most rapidly growing classes of malware. In Q1 2019,
droppers are in the 2nd or 3rd position in terms of share of total detected threats, while holding
nearly half of all Top 20 places in 2018. Since the droppers’ main task is to deliver payload while
sidestepping the protective barriers, and their developers are fully bent on countering detection,
this is probably one of the most dangerous classes of malware.
One of the m

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

IN THE SAME CATEGORY
bf81fc02d5aca759ffabd23be12b6c9da65da23a
fecdb304f5725b2b5da4d0fb141e57fbbeb5ebb8
Lumma Stealer – Tracking
f6def3411e6e599e769357cebe838f89053757b8
distribution channels
14083557d050b01d393e91f8850f614c965c5727

### 3.2 远程控制 (**CRITICAL**)

distribution channels
14083557d050b01d393e91f8850f614c965c5727
4d68516c9a19011e72fe0982dadd99cc1a7faf9b
fb4b166f42dfc36fdcc49ed0dde18bdc2a6774df
Download a banker to track
9f75a57eb3476bd545227bda8d54a4ad50c2c465
your parcel

[Page 5]
open a file from assets;
decrypt it using RC4 and a hardwired key;
delegate control with the help of DexClas`sLoader LoadClass.
Everything the unpacked Trojan needs to operate is in the dropper’s APK file: all activity, receiver
and service records are written down in the manifest, the pictures are where they should be (with
unique names generated for all objects). As Hqwar doesn’t “drop” the APK file but only loads the

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

over 200,000 Trojans packed using Hqwar. When decrypting and unpacking these malicious
malware attribution and next-gen IoT
objects, we found that almost 80% of them are financial threats, while nearly one third represent honeypots
the banking Trojan family of Faketoken. In fact, it was the first ever banking Trojan whose authors
MARCO PREUSS,DENIS LEGEZO,COSTIN RAIU,
began using Hqwar. KURT BAUMGARTNER,DAN DEMETER,YAROSLAV SHMELEV
The Top 10 list of payloads most often bundled with Hqwar features such widely distributed Trojans

over 200,000 Trojans packed using Hqwar. When decrypting and unpacking these malicious
malware attribution and next-gen IoT
objects, we found that almost 80% of them are financial threats, while nearly one third represent honeypots
the banking Trojan family of Faketoken. In fact, it was the first ever banking Trojan whose authors
MARCO PREUSS,DENIS LEGEZO,COSTIN RAIU,
began using Hqwar. KURT BAUMGARTNER,DAN DEMETER,YAROSLAV SHMELEV
The Top 10 list of payloads most often bundled with Hqwar features such widely distributed Trojans

### 3.4 C2 反检测 (**HIGH**)

[Page 6]
A portion of line decryption code from Hqwar (left) and Fakeinst.hq (right)
A setup was used in which a portion of code was loaded from AES-encrypted asset files. It is FROM THE SAME AUTHORS
worth noting that in Fakeinst.hq one of the encrypted files was an APK file, while the other one
was a DEX file used to install a secondary APK (payload). This made for a triple matryoshka: the
IT threat evolution in Q2 2021.

### 3.5 勒索软件 (**HIGH**)

come “packaged” with this dropper. Yet, beginning Q4 2018, we observe its decline. The likely reason
is the tool is not updated frequently enough by its author, causing a customer outflow.
Number of Hqwar detections by unique users
The very first Trojan packed with Hqwar was a piece of ransomware targeting Russian users. This is
how this disgrace introduced itself to the victims, impersonating the Ministry of Internal Affairs
(note that Hqwar was built by a Russian-speaking author, and many of its clients prey on Russian
users):

### 3.7 蠕虫传播 (**HIGH**)

nearly half of all Top 20 places in 2018. Since the droppers’ main task is to deliver payload while
sidestepping the protective barriers, and their developers are fully bent on countering detection,
this is probably one of the most dangerous classes of malware.
One of the most dangerous and widely spread families of Trojan droppers is Trojan-
Dropper.AndroidOS.Hqwar. Originally created as a MaaS infrastructure, today Hqwar is used for
both small-scale attacks and big ones affecting thousands of users all over the world.

The Top 10 list of payloads most often bundled with Hqwar features such widely distributed Trojans
26 AUG 2020, 2:00PM
as Asacub, Marcher and Svpeng. On several occasions, the dropper was carrying Korean bankers of GReAT Ideas. Powered by SAS: threat
the Wroba family and such famous SMS Trojans as Opfake and Fakeinst. But their authors seem to actors advance on new fronts
have used Hqwar just to try things out, so to speak: these “matryoshkas” did not gain much IVAN KWIATKOWSKI,MAHER YAMOUT,NOUSHIN SHABAB,
popularity. All in all, we know of 22 families of different Trojans packed with Hqwar, which shows how PIERRE DELCHER,FÉLIX AIME,GIAMPAOLO DEDOLA,
SANTIAGO PONTIROLI

### 3.8 权限滥用 (**HIGH**)

[Page 13]
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
| `android.hqwar.gen50116` | 域名类型 |
| `www.kaspersky.com` | 域名类型 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `https://www.kaspersky.com/android-security` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
8. 其他行为见详细信息...
