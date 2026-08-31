# Android Malware - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: provides a
> **恶意软件名称**: Android Malware
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 巴西
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
gbhackers.
Android Malware
Warning !! Hackers
Launching Fully Equipped
Android RAT via WhatsApp
& SMS to Spy Your Android
ByBalaji August 31, 2019

[Page 2]
Researchersg disbcovheread ac fuklly eequripspe.d Android RAT called “BRATA”
that exclusively attacking the Android users in Brazil and launching
via different sources including WhatsApp, SMS, and sponsor links in
Google Search.
Attackers spreading this BRATA Android RAT since January 2019,
initially hosted in Google play store and, some of the other 3rd party
app stores.
Researchers Uncovered almost 20 different variants that ap

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

registered Google accounts, but missing permissions to
properly execute the malware, and hardware information.”
After completing the infection, malware authors provides a
command “Launch/Uninstall ” to uninstall the malware and remove
the tract of the infection or launching any particular application.
Kaspersky researchers detected this malware as
“HEUR:Backdoor.AndroidOS.Brata” and they requested the Android

### 3.7 蠕虫传播 (**HIGH**)

that exclusively attacking the Android users in Brazil and launching
via different sources including WhatsApp, SMS, and sponsor links in
Google Search.
Attackers spreading this BRATA Android RAT since January 2019,
initially hosted in Google play store and, some of the other 3rd party
app stores.
Researchers Uncovered almost 20 different variants that appeared in

Android Malware
Warning !! Hackers
Launching Fully Equipped
Android RAT via WhatsApp
& SMS to Spy Your Android
ByBalaji August 31, 2019


Warning !! Hackers
Launching Fully Equipped
Android RAT via WhatsApp
& SMS to Spy Your Android
ByBalaji August 31, 2019


---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到2类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **蠕虫传播** (HIGH): 发现
