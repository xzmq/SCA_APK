# [Page 1] - 分析报告

> **来源**: Trend Micro
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: [Page 1]
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 水坑攻击, 即时通讯软件传播, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
TrendLabs
[Page 2]
Table of Contents
Campaign Analysis ....................................................................................................................................... 2
Correlation ..................................................................................................................................................... 6
AnubisSpy’s Capabilities .............................................................................................................................. 8
AnubisSpy’s Modules ............................................................

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account, device_info

[Page 3]
Android malware like ransomware exemplify how the platform can be lucrative for cybercriminals. But
there are also other threats stirring up as of late: attacks that spy on and steal data from specific targets.
More than the malware involved, these also demonstrate how attackers are crossing over between
desktops and their mobile counterparts.
Take for instance several malicious apps we came across with cyberespionage capabilities, targeting

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

[Page 9]
The malicious modules of all the AnubisSpy samples are almost the same. Our analyses are from a
sample with the package name cc.solidaritycc (SHA256:
d627f9d0e2711d59cc2571a11d16c950adadba55d95fd4c55638af6a97d32b23).
AnubisSpy can steal messages (SMS), photos, videos, contacts, email accounts, calendar events, and
browser histories (i.e., Chrome and Samsung Internet Browser). It can also take screenshots and record
audio, including calls. It can monitor the victim through apps installed on the device, such as Skype,

since been taken down — and third-party app marketplaces.
We named these malicious apps AnubisSpy (ANDROIDOS_ANUBISSPY) as all the malware’s payload is
a package called watchdog. We construe AnubisSpy to be linked to the cyberespionage campaign
Sphinx (APT-C-15) based on shared file structures and command-and-control (C&C) server as well as
targets. It’s also possible that while AnubisSpy’s operators may also be Sphinx’s, they could be running
separate but similar campaigns.
We disclosed our findings to Google and worked with them to take down the apps on Google Play.

since been taken down — and third-party app marketplaces.
We named these malicious apps AnubisSpy (ANDROIDOS_ANUBISSPY) as all the malware’s payload is
a package called watchdog. We construe AnubisSpy to be linked to the cyberespionage campaign
Sphinx (APT-C-15) based on shared file structures and command-and-control (C&C) server as well as
targets. It’s also possible that while AnubisSpy’s operators may also be Sphinx’s, they could be running
separate but similar campaigns.
We disclosed our findings to Google and worked with them to take down the apps on Google Play.

since been taken down — and third-party app marketplaces.
We named these malicious apps AnubisSpy (ANDROIDOS_ANUBISSPY) as all the malware’s payload is
a package called watchdog. We construe AnubisSpy to be linked to the cyberespionage campaign
Sphinx (APT-C-15) based on shared file structures and command-and-control (C&C) server as well as
targets. It’s also possible that while AnubisSpy’s operators may also be Sphinx’s, they could be running
separate but similar campaigns.
We disclosed our findings to Google and worked with them to take down the apps on Google Play.

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

browser histories (i.e., Chrome and Samsung Internet Browser). It can also take screenshots and record
audio, including calls. It can monitor the victim through apps installed on the device, such as Skype,
WhatsApp, Facebook, and Twitter, among others.
After the data are collected, they are encrypted and sent to the (C&C) server. AnubisSpy can also self-
destruct to cover its tracks. It can run commands and delete files on the device, as well as install and
uninstall Android Application Packages (APKs).
AnubisSpy’s code is well constructed, indicating at least the attackers’ know-how. Below is a

Figure 19: Code snippets showing how the Comm Module works

[Page 16]
To evade traffic inspection, all keywords in the request body are replaced based on protocol_strings
specified in the configuration file:
Original Keyword Replaced Keyword
request choux

### 3.5 勒索软件 (**HIGH**)

Use of this information constitutes acceptance for use in an “as is” condition.

[Page 3]
Android malware like ransomware exemplify how the platform can be lucrative for cybercriminals. But
there are also other threats stirring up as of late: attacks that spy on and steal data from specific targets.
More than the malware involved, these also demonstrate how attackers are crossing over between
desktops and their mobile counterparts.

### 3.6 广告欺诈 (**MEDIUM**)

[Page 7]
Sphinx reportedly uses the watering hole technique via social media sites to deliver its payloads —
mainly a customized version of njRAT. The Sphinx campaign operators cloaked their malware with Word,
PDF, image, and application (i.e., Flash) icons to dupe recipients into clicking them. Sphinx was active
between June 2014 and November 2015, but timestamps of the malware indicate the attacks started as
early as 2011.
A WHOIS query of the C&C server showed that it abused a legitimate managed hosting service provider

### 3.7 蠕虫传播 (**HIGH**)

AnubisSpy can steal messages (SMS), photos, videos, contacts, email accounts, calendar events, and
browser histories (i.e., Chrome and Samsung Internet Browser). It can also take screenshots and record
audio, including calls. It can monitor the victim through apps installed on the device, such as Skype,
WhatsApp, Facebook, and Twitter, among others.
After the data are collected, they are encrypted and sent to the (C&C) server. AnubisSpy can also self-
destruct to cover its tracks. It can run commands and delete files on the device, as well as install and
uninstall Android Application Packages (APKs).

The malicious modules of all the AnubisSpy samples are almost the same. Our analyses are from a
sample with the package name cc.solidaritycc (SHA256:
d627f9d0e2711d59cc2571a11d16c950adadba55d95fd4c55638af6a97d32b23).
AnubisSpy can steal messages (SMS), photos, videos, contacts, email accounts, calendar events, and
browser histories (i.e., Chrome and Samsung Internet Browser). It can also take screenshots and record
audio, including calls. It can monitor the victim through apps installed on the device, such as Skype,
WhatsApp, Facebook, and Twitter, among others.

### 3.8 权限滥用 (**HIGH**)

Screenshot Module works only on rooted devices.
Figure 25: Screenshot Module’s intervals for taking screenshots (top) and how it checks whether the device is
rooted or not (bottom)
It first gets the device’s current, overlaying activity. It takes a screenshot of it if its package name is in
the list from its configuration file. If it fails to get the activity or if the package list is empty, it will just take
a screenshot of current screen regardless of the activities running on top. A screenshot is taken by
running screencap. After it is compressed, it is sent to the Format Module and processed as a JSON file

Chrome and Samsung Internet Browser, photos, and videos. If any of the device content changes, a
specific module will be invoked to process the new/updated data.
Figure 14: Code snapshot showing how new/changed data is processed
Based on the configuration and device-rooted status, it will call the Android Application Package (APK)
Manipulate Module to install itself as a system application then install an embedded APK decrypted from
assets. In one of the samples we analyzed though, there was no embedded APK in the assets folder.
Decrypt embedded APK

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `android.service.notification.NotificationListenerService` | 域名类型 |
| `com.android.chrome` | 域名类型 |
| `com.facebook.katana` | 域名类型 |
| `com.facebook.orca` | 域名类型 |
| `com.google.android.talk` | 域名类型 |
| `com.sec.android.app.sbrowser` | 域名类型 |
| `com.skype.raider` | 域名类型 |
| `com.viber.voip` | 域名类型 |
| `mobi.mgeek.TunnyBrowser` | 域名类型 |
| `www.trendmicro.com` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `001234ABDE9217910000DEC4FEDB120003243BC00221296470103FE000AAB201` | 恶意文件 |
| `06cb3f69ba0dd3a2a7fa21cdc1d8b36b36c2a32187013598d3d51cfddc829f49` | 恶意文件 |
| `0714b516ac824a324726550b45684ca1f4396aa7f372db6cc51b06c97ea24dfd` | 恶意文件 |
| `0cab88bb37fee06cf354d257ec5f27b0714e914b8199c03ae87987f6fa807efc` | 恶意文件 |
| `7eeadfe1aa5f6bb827f9cb921c63571e263e5c6b20b2e27ccc64a04eba51ca7a` | 恶意文件 |
| `ad5babecf3a21dd51eee455031ab96f326a9dd43a456ce6e8b351d7c4347330f` | 恶意文件 |
| `d627f9d0e2711d59cc2571a11d16c950adadba55d95fd4c55638af6a97d32b23` | 恶意文件 |
| `e00655d06a07f6eb8e1a4b1bd82eefe310cde10ca11af4688e32c11d7b193d95` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 水坑攻击, 即时通讯软件传播, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): twitter
4. **勒索软件** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
