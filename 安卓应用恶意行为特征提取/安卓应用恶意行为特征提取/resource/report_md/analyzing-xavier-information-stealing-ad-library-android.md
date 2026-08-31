# Cyber Threats - 分析报告

> **来源**: Trend Micro
> **发布日期**: Jun 13, 2017
> **作者**: Ecular Xu
Jun
> **恶意软件名称**: Cyber Threats
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 欧洲, 亚洲, 越南
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Cyber Threats
Xavier: An Information-Stealing Ad Library on Android
We discovered a Trojan Android ad library called Xavier that steals a user’s information. Xavier’s impact has been widespread, with more than 800 applications embedding the ad
library’s SDK having been downloaded millions of times from Google Play.
By: Ecular Xu
Jun 13, 2017
Read time: 4 min (1132 words)

Updated on July 4, 2017, 8:19 PM PDT to correct the malware distribution chart.
We have recently discovered a Trojan Android ad library called Xavier (Detected by Trend Micro
as ANDROIDOS_XAVIER.AXM) that steals and

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

[Page 1]
Cyber Threats
Xavier: An Information-Stealing Ad Library on Android
We discovered a Trojan Android ad library called Xavier that steals a user’s information. Xavier’s impact has been widespread, with more than 800 applications embedding the ad
library’s SDK having been downloaded millions of times from Google Play.
By: Ecular Xu

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

it can do this silently if the device is rooted.

[Page 7]
It performed communication with the Command & Control (C&C) server without encryption.
However, all constant strings were encrypted in the code.
The second variant that emerged from the AdDown family was called nativemob. Comparing
nativemob with joymobile, we can see that the former has had its code structure rearranged. It

it can do this silently if the device is rooted.

[Page 7]
It performed communication with the Command & Control (C&C) server without encryption.
However, all constant strings were encrypted in the code.
The second variant that emerged from the AdDown family was called nativemob. Comparing
nativemob with joymobile, we can see that the former has had its code structure rearranged. It

it can do this silently if the device is rooted.

[Page 7]
It performed communication with the Command & Control (C&C) server without encryption.
However, all constant strings were encrypted in the code.
The second variant that emerged from the AdDown family was called nativemob. Comparing
nativemob with joymobile, we can see that the former has had its code structure rearranged. It

### 3.4 C2 反检测 (**HIGH**)

with some notable features that differentiate it from the earlier ad library. First, it comes with an
embedded malicious behavior that downloads codes from a remote server, then loads and
executes it. Second, it goes to great lengths to protect itself from being detected through the use
of methods such as String encryption, Internet data encryption, and emulator detection.

Xavier’s stealing and leaking capabilities are difficult to detect because of a self-protect
mechanism that allows it to escape both static and dynamic analysis. In addition, Xavier also has

### 3.7 蠕虫传播 (**HIGH**)

[Page 1]
Cyber Threats
Xavier: An Information-Stealing Ad Library on Android
We discovered a Trojan Android ad library called Xavier that steals a user’s information. Xavier’s impact has been widespread, with more than 800 applications embedding the ad
library’s SDK having been downloaded millions of times from Google Play.
By: Ecular Xu
Jun 13, 2017

### 3.8 权限滥用 (**HIGH**)

[Page 6]
Other than collecting and leaking user info, this ad library is capable of installing other APKs, and
it can do this silently if the device is rooted.

[Page 7]
It performed communication with the Command & Control (C&C) server without encryption.

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.google.market` | 域名类型 |
| `com.google.vending` | 域名类型 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @facebook | C2/通信 |
| @google | C2/通信 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): 发现
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
5. **权限滥用** (HIGH): 发现
