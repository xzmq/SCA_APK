# Android AdDisplay using anti-bouncer - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: were so lazy that instead of
> **恶意软件名称**: Android AdDisplay using anti-bouncer
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等)
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Android AdDisplay using anti-bouncer
technique
In order to help make Google Play a safer place for Android users, ESET continues to monitor
the official Android app market for malicious or potentially unwanted applications.
Lukas Stefanko
08 Oct 2015 • 5 min. read
[Page 2]
One of the most common ways of spreading Android malware – including malware found on the
official Google Play Store – is by masquerading as a legitimate popular application. The last such
example that we discussed on WeLiveSecurity was a fake Dubsmash app and
Android/TrojanDropper.Mapin compromising tens of thousan

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

allowed them to slip by Google Play's security filter, Bouncer. The apps’ malicious payload wasn’t
activated if they detected it was running in an emulator, or on an IP address linked with Google’s
WHOIS information. As a second technique for staying under the radar, the app behaved
innocuously, unless the C&C server instructed the bot to display ads. This is one example when
even an AdDisplay Potentially Unwanted Application could be very annoying and hard to uninstall
from a device.
More information

### 3.4 C2 反检测 (**HIGH**)

While ad-supported applications are common in the Android ecosystem, there’s a clear boundary
of behaviors that ESET cannot condone. These particular AdDisplay PUAs contain specialized self-
protection functionalities that not only make the removal of the app from the Android device more
difficult, but also help it evade detection by Google Bouncer in the first place.
When users realize that the apps are exhibiting very unusual behavior and try to uninstall them,
they will find that this is far from easy – the apps will ask the users to activate the device’s
administrator rights. Thus, users may have difficulty with removing this AdDisplay threat. This

### 3.7 蠕虫传播 (**HIGH**)

08 Oct 2015 • 5 min. read

[Page 2]
One of the most common ways of spreading Android malware – including malware found on the
official Google Play Store – is by masquerading as a legitimate popular application. The last such
example that we discussed on WeLiveSecurity was a fake Dubsmash app and
Android/TrojanDropper.Mapin compromising tens of thousands of users' devices. In order to help

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.Pou.cheats.coins.money` | 域名类型 |
| `com.SubWay.cheats.Keys.Coins.Money.Surfers` | 域名类型 |
| `com.sub.Gold.way.Money.Guid.apk` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等) |
| **综合风险** | **CRITICAL** | 检测到3类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **C2 反检测** (HIGH): 发现
3. **蠕虫传播** (HIGH): 发现
