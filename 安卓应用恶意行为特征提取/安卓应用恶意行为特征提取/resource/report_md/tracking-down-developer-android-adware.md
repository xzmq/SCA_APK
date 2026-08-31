# Tracking down the developer of - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: ized App
> **恶意软件名称**: Tracking down the developer of
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
ESET Research
Tracking down the developer of
Android adware affecting millions of
users
ESET researchers discovered a year-long adware campaign on Google Play and tracked down
its operator. The apps involved, installed eight million times, use several tricks for stealth and
persistence.
Lukas Stefanko
24 Oct 2019 • 10 min. read
[Page 2]
[Page 3]
We detected a large adware campaign running for about a year, with the involved apps installed
eight million times from Google Play alone.
We identified 42 apps on Google Play as belonging to the campaign, which had been running since
July 201

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

Android adware affecting millions of
users
ESET researchers discovered a year-long adware campaign on Google Play and tracked down
its operator. The apps involved, installed eight million times, use several tricks for stealth and
persistence.
Lukas Stefanko
24 Oct 2019 • 10 min. read

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

Package name Hash Installs
com.ngocph.masterfree c1c958afa12a4fceb595539c6d208e6b103415d7 5,000,000+
com.mghstudio.ringtonemaker 7a8640d4a766c3e4c4707f038c12f30ad7e21876 500,000+
com.hunghh.instadownloader 8421f9f25dd30766f864490c26766d381b89dbee 500,000+
com.chungit.tank1990 237f9bfe204e857abb51db15d6092d350ad3eb01 500,000+
com.video.downloadmasterfree 43fea80444befe79b55e1f05d980261318472dff 100,000+
com.massapp.instadownloader 1382c2990bdce7d0aa081336214b78a06fceef62 100,000+

All the apps provide the functionality they promise, besides working as adware. The adware
functionality is the same in all the apps we analyzed. [Note: The analysis of the functionality below
describes a single app, but applies to all apps of the Android/AdDisplay.Ashas family.]
Once launched, the app starts to communicate with its C&C server (whose IP address is base64-
encoded in the app). It sends “home” key data about the affected device: device type, OS version,
language, number of installed apps, free storage space, battery status, whether the device is rooted
dD l d bl d d h h F b k dFBM i ll d

### 3.6 广告欺诈 (**MEDIUM**)

[Page 1]
ESET Research
Tracking down the developer of
Android adware affecting millions of
users
ESET researchers discovered a year-long adware campaign on Google Play and tracked down
its operator. The apps involved, installed eight million times, use several tricks for stealth and

### 3.7 蠕虫传播 (**HIGH**)

[Page 12]
Figure 10. The malicious developer’s apps published on the App Store which don’t contain the Ashas adware
Searching further for the malicious developer’s activities, we also discovered his Youtube channel
propagating the Ashas adware and his other projects. As for the Ashas family, one of the associated
promotional videos, “Head Soccer World Champion 2018 - Android, ios” was viewed almost three
million times and two others reached hundreds of thousands of views, as seen in Figure 11.

dD l d bl d d h h F b k dFBM i ll d

[Page 6]
and Developer mode enabled, and whether Facebook and FB Messenger are installed.
Figure 3. Sending information about the affected device
The app receives configuration data from the C&C server, needed for displaying ads, and for stealth
and resilience.

responsible for the activity is revealed (right).
Finally, the Ashas adware family has its code hidden under the com.google.xxx package name. This
trick – posing as a part of a legitimate Google service – may help avoid scrutiny. Some detection
mechanisms and sandboxes may whitelist such package names, in an effort to prevent wasting
resources.

[Page 9]

### 3.8 权限滥用 (**HIGH**)

describes a single app, but applies to all apps of the Android/AdDisplay.Ashas family.]
Once launched, the app starts to communicate with its C&C server (whose IP address is base64-
encoded in the app). It sends “home” key data about the affected device: device type, OS version,
language, number of installed apps, free storage space, battery status, whether the device is rooted
dD l d bl d d h h F b k dFBM i ll d

[Page 6]

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `35.198.197` | 域名类型 |
| `boxs.puzzles.Puzzlebox` | 域名类型 |
| `com.anit.bouncingball` | 域名类型 |
| `com.anthu91.soccercard` | 域名类型 |
| `com.applecat.worldchampion2018` | 域名类型 |
| `com.carlosapps.solucionariodebaldor` | 域名类型 |
| `com.chungit.basketball` | 域名类型 |
| `com.chungit.heroesjump` | 域名类型 |
| `com.chungit.tank1990` | 域名类型 |
| `com.chungit.tankbattle` | 域名类型 |
| `com.dktools.liteforfb` | 域名类型 |
| `com.doscreenrecorder.screenrecorder` | 域名类型 |
| `com.floating.tube.bymuicv` | 域名类型 |
| `com.gamebasketball.basketballperfectshot` | 域名类型 |
| `com.google.xxx` | 域名类型 |
| `com.hdevs.ringtonemaker2019` | 域名类型 |
| `com.hikeforig.hashtag` | 域名类型 |
| `com.hugofq.solucionariodebaldor` | 域名类型 |
| `com.hugofq.wismichudosmildiecisiete` | 域名类型 |
| `com.hunghh.instadownloader` | 域名类型 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @jaymin9687 | C2/通信 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): config_update
3. **广告欺诈** (MEDIUM): 发现
4. **蠕虫传播** (HIGH): 发现
5. **权限滥用** (HIGH): 发现
