# 27 FEB 2020 4 minute read - 分析报告

> **来源**: McAfee
> **发布日期**: 未知
> **作者**: SUGURU ISHIMARU
> **恶意软件名称**: 27 FEB 2020 4 minute read
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 日本, 韩国, 俄罗斯, 欧洲
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), SMiShing (短信钓鱼), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Roaming Mantis, part V
27 FEB 2020 4 minute read
// AUTHORS
SUGURU ISHIMARU
Distributed in 2019 using SMiShing and enhanced anti-
researcher techniques
Kaspersky has continued to track the Roaming Mantis campaign. The group’s attack methods have
improved and new targets continuously added in order to steal more funds. The attackers’ focus
has also shifted to techniques that avoid tracking and research: allowlist for distribution, analysis
environment detection and so on. We’ve also observed new malware families: Fakecop (also known
as SpyAgent by McAfee) and Wroba.j (also known as Fun

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, account

Distributed in 2019 using SMiShing and enhanced anti-
researcher techniques
Kaspersky has continued to track the Roaming Mantis campaign. The group’s attack methods have
improved and new targets continuously added in order to steal more funds. The attackers’ focus
has also shifted to techniques that avoid tracking and research: allowlist for distribution, analysis
environment detection and so on. We’ve also observed new malware families: Fakecop (also known
as SpyAgent by McAfee) and Wroba.j (also known as Funkybot by Fortinet).

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

[Page 9]
Operation PowerFall: CVE-
e6ae4277418323810505c28d2b6b3647 Wroba.g
2020-0986 and variants
939770e5a14129740dc57c440afbf558 Wroba.f
521312a8b5a76519f9237ec500afd534 Wroba.j

Examples of SMiShing with Android malware icons impersonating brands
In February 2020, the attacker modified a SMiShing message from a spoofed absence notification
to “delivering free masks for the coronavirus issue” in Japan, according to a warning by Japan
Cybercrime Control Center (JC3). This once again shows that criminals always make use of hot Table of Contents
topics in their activities.
Distribution of Wroba.g via SMiShing
with impersonated brands

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

only on the Korean page. It’s a allowlist feature to evade security researchers. When a user visits module of Wroba.g
the landing page, they have to enter their phone number for confirmation. If the phone number is
Wroba.g is targeting carrier billing and
on the allowlist, the landing page distributes a malicious app.apk: online banks in Japan
Wroba.j and Fakecop discovered in 2019
Conclusion

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

JOHN HULTQUIST,BRIAN BARTHOLOMEW,SUGURU ISHIMARU,
The classes${num}.dex marked with a red square is the actual malicious loader module. All the
VITALY KAMLUK,SEONGSU PARK,YUSUKE NIWA,
other DEX files are simply junk code. However, the encrypted payload of Wroba.g is still under the
MOTOHIKO SATO
assets directory and can be decrypted by the simple python script described in our previous
blogpost.

only
page for Korea only
The Roaming Mantis actor also employed a new feature in their Wroba.g landing page – currently Multidex obfuscation trick in a loader
only on the Korean page. It’s a allowlist feature to evade security researchers. When a user visits module of Wroba.g
the landing page, they have to enter their phone number for confirmation. If the phone number is
Wroba.g is targeting carrier billing and
on the allowlist, the landing page distributes a malicious app.apk: online banks in Japan

### 3.5 勒索软件 (**HIGH**)

IT threat evolution Q3 2020
FunkyBot: A New Android Malware Family Targeting Japan
These blogposts provide some interesting updates on Roaming Mantis activities during 2019.
Targeted ransomware: it’s not
just about encrypting your
data!
Example of md5 hashes for each APK

### 3.6 广告欺诈 (**MEDIUM**)

When the malware detects a specific package of a Japanese online bank or specific mobile carriers FABIO ASSOLINI
on the infected device, it connects in the background to a hardcoded malicious account of
pinterest.com to fetch a phishing site with an alert message. The message claims that it has
blocked unauthorized access from a third party and asks the user to click on a button to confirm
they want to proceed. If the user clicks the button, they will be redirected to a phishing site:
Redirecting to a phishing site via malicious account on pinterest.com
The targeted packages for online banks and mobile carriers correspond to the relevant accounts

### 3.7 蠕虫传播 (**HIGH**)

LODEINFO 2022, part I
Based on our telemetry data, detection rates of both malicious programs were very low. We believe
that this was a test by the attacker. However, the most alarming thing we discovered was the
following SMS spamming function in Wroba.j:
Roaming Mantis reaches
Europe
Roaming Mantis dabbles in

### 3.8 权限滥用 (**HIGH**)

[Page 11]
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
| `jp.co.japannetbank.smtapp.balance` | 域名类型 |
| `jp.co.jibunbank.jibunmain` | 域名类型 |
| `jp.co.netbk.smartkey.SSNBSmartkey` | 域名类型 |
| `jp.co.rakuten_bank.rakutenbank` | 域名类型 |
| `jp.co.sevenbank.AppPassbook` | 域名类型 |
| `jp.co.smbc.direct` | 域名类型 |
| `jp.japanpost.jp_bank.FIDOapp` | 域名类型 |
| `jp.mufg.bk.applisp.app` | 域名类型 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @ninoseki | C2/通信 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等), SMiShing (短信钓鱼), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, account
2. **远程控制** (CRITICAL): config_update
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): twitter
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
