# Rooting Pokémons in Google Play Store - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: ROMAN UNUCHEK
> **恶意软件名称**: Rooting Pokémons in Google Play Store
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Rooting Pokémons in Google Play Store
MALWARE DESCRIPTIONS 14 SEP 2016 2 minute read
// AUTHORS
ROMAN UNUCHEK
A few days ago we reported to Google the existence of a new malicious app in the Google Play
Store. The Trojan presented itself as the “Guide for Pokémon Go”. According to the Google Play
Store it has been downloaded more than 500,000 times. Our data suggests there have been at
least 6,000 successful infections, including in Russia, India and Indonesia. However, since the app is
oriented towards English-speaking users, people in such geographies, and more, are also likely to
h

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: account

[Page 4]
target, or those which it suspects are a sandbox/virtual machine, for example. Among other things,
this provides an additional layer of protection for the malware.
Still Stealing
Upon receiving the second request, the CnC server will send the Trojan a JSON file containing a
URL. The Trojan downloads file from the specified URL, decrypts it and executes. In our case the
Trojan downloaded a file detected as HEUR:Trojan.AndroidOS.Ztorg.a. This file is obfuscated too.

### 3.2 远程控制 (**CRITICAL**)

install or uninstall another app, then checks to see if that app runs on a real device or on a virtual
machine. If it turns out that it’s dealing with a device, the Trojan will wait for a further two hours
before starting its malicious activity. Leaking ads
The first thing it does is connect to its command-and-control (CnC) server and upload data about
the device, including country, language, device model and OS version.
Pocket cryptofarms
If the server wants the Trojan to continue it will respond with an ID string. Only if the Trojan receives

install or uninstall another app, then checks to see if that app runs on a real device or on a virtual
machine. If it turns out that it’s dealing with a device, the Trojan will wait for a further two hours
before starting its malicious activity. Leaking ads
The first thing it does is connect to its command-and-control (CnC) server and upload data about
the device, including country, language, device model and OS version.
Pocket cryptofarms
If the server wants the Trojan to continue it will respond with an ID string. Only if the Trojan receives

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

Comment Lumma Stealer – Tracking
distribution channels
This site uses Akismet to reduce spam. Learn how your comment data is processed.
Download a banker to track
ARKADIY your parcel
Posted on September 14, 2016. 2:28 pm
Please explain how can an android application receive a rooting access priviledge?

### 3.4 C2 反检测 (**HIGH**)

URL. The Trojan downloads file from the specified URL, decrypts it and executes. In our case the
Trojan downloaded a file detected as HEUR:Trojan.AndroidOS.Ztorg.a. This file is obfuscated too.
After execution, the Trojan will drop and download some more files. All downloaded files are
encrypted and most of them are local root exploit packs for vulnerabilities dating from 2012 to
2015, including one that was previously used by Hacking Team.
These other files represent additional modules of the Trojan and are detected by Kaspersky Lab as:
HEUR:Backdoor.AndroidOS.Ztorg.c, HEUR:Trojan.AndroidOS.Muetan.b,

### 3.5 勒索软件 (**HIGH**)

Posted on September 15, 2016. 1:23 pm
I’ve downloaded sample for 8CB3A269E50CA1F9E958F685AE4A073C . So there is no MainActivity
Ymir: new stealthy
there and NativeActivity, but malware is working on my Android emulator. Could you please say ransomware in the wild
something about technique that it uses to start the app ? Because I don’t see MainActivity class
when I decompile it with apktool. And there is no such class in DEX file.
QSC: A multi-plugin

### 3.6 广告欺诈 (**MEDIUM**)

have been hit.
Analysis reveals that the app contains a malicious piece of code that downloads rooting malware –
malware capable of gaining access to the core Android operating system, in this case for the
purposes of unsolicited app install and adware.
GREAT WEBINARS
Kaspersky Lab products detect the Trojan as HEUR:Trojan.AndroidOS.Ztorg.ad.
13 MAY 2021, 1:00PM

### 3.8 权限滥用 (**HIGH**)

[Page 1]
Rooting Pokémons in Google Play Store
MALWARE DESCRIPTIONS 14 SEP 2016 2 minute read
// AUTHORS
ROMAN UNUCHEK

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

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
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
8. 其他行为见详细信息...
