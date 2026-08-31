# Fernando Ruiz MAR 03, 2020 11 MIN READ - 分析报告

> **来源**: McAfee
> **发布日期**: MAR 03, 2020
> **作者**: Anuradha
> **恶意软件名称**: Fernando Ruiz MAR 03, 2020 11 MIN READ
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 美国, 巴西
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 社交媒体传播, 恶意广告
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Android/LeifAccess.A is the Silent Fake Reviewer
Trojan
Fernando Ruiz MAR 03, 2020 11 MIN READ
The McAfee Mobile Research team has identified an Android malware family dubbed
Android/LeifAccess.A that has been active since May 2019. This trojan was discovered
globally with localized versions but has a much higher prevalence in the USA and Brazil.
As part of the payload, this trojan can abuse OAuth leveraging accessibility services to
automatically create accounts in the name of a victim’s legitimate email in multiple
third-party apps. Using the same approach, it can create fake review

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: contacts, account

More from McAfee Labs
Learn to Identify and Astaroth: Banking Android Malware Think Before You Android M
Avoid Malicious Trojan Abusing Promises Energy Click: EPI PDF’s Hidden Targets In
Browser Extensions GitHub for Resilience Subsidy to Steal Extras Banking U
In this guide, you will learn by Harshil Patel and FAuinthaonrecdi ably DZeaPteang Chen Authored by: Anuradha & FAuinthaonrecdi ably I
about the advantages and Prabudh Chakravorty Recently, we identified an Prabudh PDF converting MMciAnfeee C’sr Myopb
security risks of browser *EDITOR’S NOTE: Special active Android phishing software can be super Team discov

### 3.2 远程控制 (**CRITICAL**)

com.services.jifat.qaxtitmumdd
533a395ed16143bbe6f258f3146ea0ea3c56f71e889ace81039800803d0b1e18
com.services.xvpyv.tteawsribdsvi
6755f708d75a6b8b034eae9bcb6176679d23f2dc6eb00b8656d00f8ee0ec26c1
com.services.myzmuexri.nrphcanr
URLS
adsnative123[.]com

This malware has not been identified in the official Android store so some of the potential
distribution methods that we identified are related to social media, gaming platforms,
malvertising and the direct download of the APK files from the Command and Control
(C&C) Server.
Social Engineering to get Accessibility Services
kcabdeeF
Products Features Resources About Us Why McAfee Support Log in

Meanwhile, many targeted apps affected for fake reviews are on Google Play.
This malware has not been identified in the official Android store so some of the potential
distribution methods that we identified are related to social media, gaming platforms,
malvertising and the direct download of the APK files from the Command and Control
(C&C) Server.
Social Engineering to get Accessibility Services
kcabdeeF

Meanwhile, many targeted apps affected for fake reviews are on Google Play.
This malware has not been identified in the official Android store so some of the potential
distribution methods that we identified are related to social media, gaming platforms,
malvertising and the direct download of the APK files from the Command and Control
(C&C) Server.
Social Engineering to get Accessibility Services
kcabdeeF

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

Accessibility services were designed to assist users with disabilities, or while they were
Topics At McAfee English
otherwise unable to fully interact with the device. However, as we have observed in
banking trojans and other mobile threats, the accessibility services could also be abused
by malware authors to perform malicious activities without user interaction. In recent
versions of Android, Google limited the number of apps with accessibility services
permission on Google Play and moved some functionality to other newly created APIs to

Accessibility services were designed to assist users with disabilities, or while they were
Topics At McAfee English
otherwise unable to fully interact with the device. However, as we have observed in
banking trojans and other mobile threats, the accessibility services could also be abused
by malware authors to perform malicious activities without user interaction. In recent
versions of Android, Google limited the number of apps with accessibility services
permission on Google Play and moved some functionality to other newly created APIs to

### 3.4 C2 反检测 (**HIGH**)

Android/LeifAccess.A stores a Hashtable map, in a SharedPreferences XML format, where
the key is the function name and the value is the parameter used by the commands. To
avoid detection, the real function names (plain text) and parameters are obfuscated,
encrypted, salted and/or one-way hashed (md5 or sha-1).
Values are stored as obfuscated strings using data compression with zip.deflater
and base64.enconde as defense evasion techniques. Some strings are obfuscated
more than one time with the same algorithm.

### 3.6 广告欺诈 (**MEDIUM**)

As part of the payload, this trojan can abuse OAuth leveraging accessibility services to
automatically create accounts in the name of a victim’s legitimate email in multiple
third-party apps. Using the same approach, it can create fake reviews on the Google Play
store to manipulate app rankings, perform ad-fraud (clicker functionality), update itself
and execute arbitrary remote code, among other functionalities.
Meanwhile, many targeted apps affected for fake reviews are on Google Play.
This malware has not been identified in the official Android store so some of the potential

legitimate click coming from a user clicking a banner in the context of a legitimate
application, evading the SDK integration which also contributes to keep a relatively small
file size.
The adware JSON structure includes:
Furthermore, this malware can show real ads in full screen out of the context of any app
after unlocking the device if it receives the proper commands, or based on a certain
frequency defined by the C&C. Also, it can show an overlay icon redirecting to ads as a

As part of the payload, this trojan can abuse OAuth leveraging accessibility services to
automatically create accounts in the name of a victim’s legitimate email in multiple
third-party apps. Using the same approach, it can create fake reviews on the Google Play
store to manipulate app rankings, perform ad-fraud (clicker functionality), update itself
and execute arbitrary remote code, among other functionalities.
Meanwhile, many targeted apps affected for fake reviews are on Google Play.
This malware has not been identified in the official Android store so some of the potential

### 3.8 权限滥用 (**HIGH**)

The McAfee Mobile Research team has identified an Android malware family dubbed
Android/LeifAccess.A that has been active since May 2019. This trojan was discovered
globally with localized versions but has a much higher prevalence in the USA and Brazil.
As part of the payload, this trojan can abuse OAuth leveraging accessibility services to
automatically create accounts in the name of a victim’s legitimate email in multiple
third-party apps. Using the same approach, it can create fake reviews on the Google Play
store to manipulate app rankings, perform ad-fraud (clicker functionality), update itself

The adware JSON structure includes:
Furthermore, this malware can show real ads in full screen out of the context of any app
after unlocking the device if it receives the proper commands, or based on a certain
frequency defined by the C&C. Also, it can show an overlay icon redirecting to ads as a
floating overlay.
Arbitrary shortcuts can be created in the home screen based on the parameters
received:

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `aboutme.google.com` | 域名类型 |
| `alibaba.intl.android.apps.poseidon` | 域名类型 |
| `android-developers.googleblog.com` | 域名类型 |
| `api.adsnativeXXX.com` | 域名类型 |
| `cdn.discordapp.com` | 域名类型 |
| `cdn.leadcdnbXXX.com` | 域名类型 |
| `com.android.vending` | 域名类型 |
| `com.netshoes.app` | 域名类型 |
| `com.services.ibgpe.hflbsqqjrmlfej` | 域名类型 |
| `com.services.jifat.qaxtitmumdd` | 域名类型 |
| `com.services.kxyiqc.zzwkzckzfiojjzpw` | 域名类型 |
| `com.services.myzmuexri.nrphcanr` | 域名类型 |
| `com.services.xvpyv.tteawsribdsvi` | 域名类型 |
| `com.services.xxxx` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `032184204b50f0634ad360a2090ea9904c012cb839b5a0364a53bf261ce8414e` | 恶意文件 |
| `0a95e9cce637a6eb71e4c663e207146fe9cde0573265d4d93433e1242189a35c` | 恶意文件 |
| `533a395ed16143bbe6f258f3146ea0ea3c56f71e889ace81039800803d0b1e18` | 恶意文件 |
| `6032c1a8b54f3daf9697a49fdd398d3ebe35f3fec3d945d6d8e9588043332969` | 恶意文件 |
| `6755f708d75a6b8b034eae9bcb6176679d23f2dc6eb00b8656d00f8ee0ec26c1` | 恶意文件 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `https://aboutme.google.com` | 钓鱼/下载 |
| `https://android-developers.googleblog.com/2018/12/in-reviews-we-trust-making-` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 社交媒体传播, 恶意广告 |
| **综合风险** | **CRITICAL** | 检测到6类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): contacts, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
7. 其他行为见详细信息...
