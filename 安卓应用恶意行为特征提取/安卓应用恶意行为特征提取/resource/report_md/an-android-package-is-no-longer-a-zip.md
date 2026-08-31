# The Issue with Android/HiddenMiner - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: The Issue with Android/HiddenMiner
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
FFOORRTTIIGGUUAARRDD LLAABBSS TTHHRREEAATT RREESSEEAARRCCHH
AAnn AAnnddrrooiidd PPaacckkaaggee iiss nnoo LLoonnggeerr aa ZZIIPP
By Axelle Apvrille| August 23, 2018
O
ver the past few years, I have been giving workshops on Android reverse engineering - my next one will be an advanced session at Virus
Bulletin in October. As most other researchers on Android, I typically start off with a slide explaining that an Android Package (APK) is just a
ZIP. Since Android 7.0, however, this is no longer true.
The Issue with Android/HiddenMiner
Everything started when I analyzed a sample of Androi

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

author(s) to track malicious samples they distribute.
-- the Crypto Girl
IOCs:
11cc2244cc33aadd2277002277ee7799aadddd1111dd112244bb11336666aaee557777ff99cc9922ccdd33330022bbdd2266886699882255cc9900bbff337777
11ff33dd5533cceebb5577336677aaee113377ccaadd22aaffaacc88bb442299aa4444cc44ddff88cc66220022cc00333300dd112255998811eeaa99665522ff
33003399bb22ffff22ee11eeddbb552222ffffaaddaaeeaaeedd88bb00cceeee11551199ccffaa5566ffaabbee77ccee66ff00ff66aa5500881166dd002266dd
77ffbbff775588ffeeaaff44dd999922bb1166bb2266aacc558822aa44bbddccffcc11aa3366bb66ff2299bb5522ffcc771133aa22bb88553377ff5544220022

### 3.3 银行木马 (**CRITICAL**)

THREAT RESEARCH
How to repair a DEX file, in which some key methods are erased with NOPs
THREAT RESEARCH
Android banking malware masquerades as Flash Player, targeting large banks and popular social media apps

[Page 13]
THREAT RESEARCH

THREAT RESEARCH
How to repair a DEX file, in which some key methods are erased with NOPs
THREAT RESEARCH
Android banking malware masquerades as Flash Player, targeting large banks and popular social media apps

[Page 13]
THREAT RESEARCH

### 3.5 勒索软件 (**HIGH**)

Threat Research
FortiGuard Labs
Threat Map
Ransomware Prevention
Connect With Us
Fortinet Community
Partner Portal

### 3.8 权限滥用 (**HIGH**)

[Page 13]
THREAT RESEARCH
Unmasking Android Malware: A Deep Dive into a New Rootnik Variant, Part III
News & Articles
News Releases
News Articles

---

## 4. IoCs (威胁指标)

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `26a718dd28c7aa7a957f11f9ae9059af5558aabfb815bf37df3274019349dd27` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **银行木马** (CRITICAL): 发现
3. **勒索软件** (HIGH): 发现
4. **权限滥用** (HIGH): 发现
