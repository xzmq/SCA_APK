# [Page 1] - 分析报告

> **来源**: Trend Micro
> **发布日期**: 未知
> **作者**: Mobile Threat Response Team
> **恶意软件名称**: [Page 1]
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 欧洲, 亚洲
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Trend Micro About TrendLabs Security Intelligence Blog
SeHarocmh:e Categories
Home » Mobile » Hacking Group Spies on Android Users in India Using PoriewSpy
Hacking Group Spies on Android Users in India Using PoriewSpy 0
Posted on:January 29, 2018 at 12:00 am Posted in:Mobile, Targeted Attacks
Author:
Mobile Threat Response Team
by Ecular Xu and Grey Guo
We have been seeing attacks that spy on and steal data from specific targets on the mobile platform
since late 2017. We discovered the malicious apps victimizing Android users in India, and believe a
hacking group—one previously known 

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account, device_info

Author:
Mobile Threat Response Team
by Ecular Xu and Grey Guo
We have been seeing attacks that spy on and steal data from specific targets on the mobile platform
since late 2017. We discovered the malicious apps victimizing Android users in India, and believe a
hacking group—one previously known for victimizing government officials—carried out the
attacks. We identified these malicious apps as PoriewSpy (detected by Trend Micro as

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

similar threats.
Indicators of Compromise (IOCs)
SHA256 App Label Package Name
cc84045618448e9684e43d5b9841aacedae94c2177 com.google.seccom.sqisland.android.swipe_im
862837c5a9e29c73716a90 urity age_viewer
34331ed1d919a1b3f6aeeb5ef7954b4101aabc54514com.google.seccom.sqisland.android.swipe_im
d67611c26f284e459024d urity age_viewer

attacks. We identified these malicious apps as PoriewSpy (detected by Trend Micro as
ANDROIDOS_PORIEWSPY.HRX). We also suspect that the group used malicious apps built
using DroidJack or SandroRAT (detected as ANDROIDOS_SANRAT.A), based on similarities in
their command-and-control (C&C) server. DroidJack is a remote access Trojan (RAT) that allows
intruders to take full control of a user’s Android device when installed.
The operators behind these malicious apps might be related to a suspected cyberespionage group
discovered in 2016, but it’s possible that the group may be launching different attacks unrelated to

attacks. We identified these malicious apps as PoriewSpy (detected by Trend Micro as
ANDROIDOS_PORIEWSPY.HRX). We also suspect that the group used malicious apps built
using DroidJack or SandroRAT (detected as ANDROIDOS_SANRAT.A), based on similarities in
their command-and-control (C&C) server. DroidJack is a remote access Trojan (RAT) that allows
intruders to take full control of a user’s Android device when installed.
The operators behind these malicious apps might be related to a suspected cyberespionage group
discovered in 2016, but it’s possible that the group may be launching different attacks unrelated to

attacks. We identified these malicious apps as PoriewSpy (detected by Trend Micro as
ANDROIDOS_PORIEWSPY.HRX). We also suspect that the group used malicious apps built
using DroidJack or SandroRAT (detected as ANDROIDOS_SANRAT.A), based on similarities in
their command-and-control (C&C) server. DroidJack is a remote access Trojan (RAT) that allows
intruders to take full control of a user’s Android device when installed.
The operators behind these malicious apps might be related to a suspected cyberespionage group
discovered in 2016, but it’s possible that the group may be launching different attacks unrelated to

### 3.5 勒索软件 (**HIGH**)

Toast Overlay Weaponized to Install Several Android Malware
April Android Security Bulletin Addresses Critical H.264 and H.265 Decoder Vulnerabilities
Untangling the Patchwork Cyberespionage Group
Learn how to protect Enterprises, Small Businesses, and Home Users from ransomware:
ENTERPRISE» SMALL BUSINESS» HOME»
Tags: PoriewSpy

### 3.6 广告欺诈 (**MEDIUM**)

88[.]150[.]227[.]71
62[.]4[.]2[.]211
Related Posts:
GhostClicker Adware is a Phantomlike Android Click Fraud
Toast Overlay Weaponized to Install Several Android Malware
April Android Security Bulletin Addresses Critical H.264 and H.265 Decoder Vulnerabilities
Untangling the Patchwork Cyberespionage Group

88[.]150[.]227[.]71
62[.]4[.]2[.]211
Related Posts:
GhostClicker Adware is a Phantomlike Android Click Fraud
Toast Overlay Weaponized to Install Several Android Malware
April Android Security Bulletin Addresses Critical H.264 and H.265 Decoder Vulnerabilities
Untangling the Patchwork Cyberespionage Group

88[.]150[.]227[.]71
62[.]4[.]2[.]211
Related Posts:
GhostClicker Adware is a Phantomlike Android Click Fraud
Toast Overlay Weaponized to Install Several Android Malware
April Android Security Bulletin Addresses Critical H.264 and H.265 Decoder Vulnerabilities
Untangling the Patchwork Cyberespionage Group

### 3.7 蠕虫传播 (**HIGH**)

their previous campaign.
PoriewSpy turns device into an audio recorder, steals other device info
Existing as far back as 2014, PoriewSpy steals sensitive information from victims’ devices such as
SMS, call logs, contacts, location, and SD card file list. It can also record victims’ voice calls. The
malware was developed from an open-source project called android-swipe-image-viewer, or
Android Image Viewer, which the malware operator/s modified to add the following components:
Permissions

### 3.8 权限滥用 (**HIGH**)

62[.]4[.]2[.]211
Related Posts:
GhostClicker Adware is a Phantomlike Android Click Fraud
Toast Overlay Weaponized to Install Several Android Malware
April Android Security Bulletin Addresses Critical H.264 and H.265 Decoder Vulnerabilities
Untangling the Patchwork Cyberespionage Group
Learn how to protect Enterprises, Small Businesses, and Home Users from ransomware:

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `230ddf07a868ccae369b891bc94a10efd928ff9c0c2fcom.google.seccom.sqisland.android.swipe_im` | 域名类型 |
| `2eb74656d63c0998ad37cf5da7e2397ddbb5523ad6com.google.seccom.sqisland.anwdroid.sipe_im` | 域名类型 |
| `34331ed1d919a1b3f6aeeb5ef7954b4101aabc54514com.google.seccom.sqisland.android.swipe_im` | 域名类型 |
| `43142a836aa0d29dfbd55b0e21bb272e4f34ffd15cccom.google.seccom.sqisland.android.swipe_im` | 域名类型 |
| `6b2ef1b5fab6fcc4167d24c391120fb5a4d1cdf9d75acom.google.seccom.sqisland.android.swipe_im` | 域名类型 |
| `aandroid.permission.ACCESS_FINE_LOCATION` | 域名类型 |
| `android.permission.ACCESS_COARSE_LOCATIOAllows` | 域名类型 |
| `android.permission.ACCESS_MOCK_LOCATION` | 域名类型 |
| `android.permission.ACCESS_NETWORK_STATE` | 域名类型 |
| `android.permission.ACCESS_WIFI_STATE` | 域名类型 |
| `android.permission.BATTERY_STATS` | 域名类型 |
| `android.permission.CHANGE_NETWORK_STATEAllows` | 域名类型 |
| `android.permission.CHANGE_WIFI_STATE` | 域名类型 |
| `android.permission.GET_ACCOUNTS` | 域名类型 |
| `android.permission.INTERNET` | 域名类型 |
| `android.permission.READ_CALL_LOG` | 域名类型 |
| `android.permission.READ_CONTACTS` | 域名类型 |
| `android.permission.READ_EXTERNAL_STORAGAllows` | 域名类型 |
| `android.permission.READ_LOGS` | 域名类型 |
| `android.permission.READ_PHONE_STATE` | 域名类型 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `http://mylocation.org` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到6类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **勒索软件** (HIGH): 发现
4. **广告欺诈** (MEDIUM): 发现
5. **蠕虫传播** (HIGH): 发现
7. 其他行为见详细信息...
