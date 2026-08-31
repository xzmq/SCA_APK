# Hiding in plain sight: PhantomLance walks into a market - 分析报告

> **来源**: 未知
> **发布日期**: May 1, 2020
> **作者**: Customize
> **恶意软件名称**: Hiding in plain sight: PhantomLance walks into a market
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 中国, 俄罗斯, 亚洲, 越南
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Hiding in plain sight: PhantomLance walks into a market
APT REPORTS 28 APR 2020 14 minute read
This website uses cookies
We use cookies to personalise content and ads, to provide social media features and to analyse our traffic. We also share information about your use of our site with our social media,
advertising and analytics partners who may combine it with other information that you’ve provided to them or that they’ve collected from your use of their services.
Show details
Allow all cookies
// AUTHORS
Customize
ALEXEY FIRSH LEV PIKMAN
In July 2019, Dr. Web reported about a backdo

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account, device_info

ALEXEY FIRSH LEV PIKMAN
In July 2019, Dr. Web reported about a backdoor trojan in Google Play, which appeared to be
Use necessary cookies only
sophisticated and unlike common malware often uploaded for stealing victims’ money or displaying
ads. So, we conducted an inquiry of our own, discovering a long-term campaign, which we dubbed
“PhantomLance”, its earliest registered domain dating back to December 2015. We found dozens of
related samples that had been appearing in the wild since 2016 and had been deployed in various

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

Version 1

[Page 4]
We attribute the latest Google Play sample (MD5: 2e06bbc26611305b28b40349a600f95c) to this
version. This is a clear payload, and unlike the other versions, it does not drop an additional
executable file. Our main theory about the reasons for all these versioning maneuvers is that the
attackers are trying to use diverse techniques to achieve their key goal, to bypass the official

### 3.4 C2 反检测 (**HIGH**)

statistics and spotted version stamps, we believe that this version is a replacement for Version 3,
which we did not observe in 2019.
Below are the most valuable points and main differences from the Version 1.
The malicious payload APK is now packed in an encrypted file in the assets directory and is
decrypted by the first stage using an AES algorithm. A decryption key and initialization vector (IV)
are located in the first 32 + 16 bytes of the encrypted payload.
This website uses cookies

### 3.7 蠕虫传播 (**HIGH**)

resemblances.

[Page 3]
Besides the attribution details, this document describes the actors’ spreading strategy, their
techniques for bypassing app market filters, malware version diversity and the latest sample
deployed in 2020, which uses Firebase to decrypt the malicious payload. We also found out that
Blackberry Cylance research team investigated this activity.

observed Version 1 samples in late 2019 and in 2017, the year that we also saw Version 3.
Functionality of all samples are similar – the main purpose of spyware was to gather sensitive
information. While the basic functionality was not very broad, and included geolocation, call logs,
contact access and SMS access, the application could also gather a list of installed applications, as
well as device information, such as model and OS version. Furthermore, the threat actor was able
to download and execute various malicious payloads, thus, adapting the payload that would be
suitable to the specific device environment, such as Android version and installed apps. This way

### 3.8 权限滥用 (**HIGH**)

No suspicious permissions are mentioned in the manifest file; instead, they are requested
dynamically and hidden inside the dex executable. This seems to be a further attempt at
circumventing security filtering. In addition to that, there is a feature that we have not seen before:
if the root privileges are accessible on the device, the malware can use a reflection call to the
undocumented API function “setUidMode” to get permissions it needs without user involvement.
This website uses cookies
We use cookies to personalise content and ads, to provide social media features and to analyse our traffic. We also share information about your use of our site with our social media,

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `188.166.203` | 域名类型 |
| `5.10.6084` | 域名类型 |
| `5.10.6090` | 域名类型 |
| `5.10.9018` | 域名类型 |
| `com.android.play.games` | 域名类型 |
| `com.android.process.gpsp` | 域名类型 |
| `com.codedexon.churchaddress` | 域名类型 |
| `com.codedexon.prayerbook` | 域名类型 |
| `com.google.android.play.games` | 域名类型 |
| `com.linevialab.ffont` | 域名类型 |
| `com.luxury.BeerAddress` | 域名类型 |
| `com.luxury.BiFinBall` | 域名类型 |
| `com.ozerlab.callrecorder` | 域名类型 |
| `com.physlane.opengl` | 域名类型 |
| `com.unianin.adsskipper` | 域名类型 |
| `com.zimice.browserturbo` | 域名类型 |
| `com.zonjob.browsercleaner` | 域名类型 |
| `cookniheasccuatui.android.zyngacdn` | 域名类型 |
| `download1825.mediafire.com` | 域名类型 |
| `nhaccuatui.android.zyngacdn.com` | 域名类型 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `https://www.antiy.net/p/analysis-of-the-attack-of-` | 钓鱼/下载 |
| `https://www.blackberry.com/content/dam/blackberry-` | 钓鱼/下载 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @kaspersky | C2/通信 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
5. **权限滥用** (HIGH): 发现
