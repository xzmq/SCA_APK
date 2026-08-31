# By: Ecular Xu - 分析报告

> **来源**: Trend Micro
> **发布日期**: Jan 08, 2019
> **作者**: Ecular Xu
Jan
> **恶意软件名称**: By: Ecular Xu
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
Malware
Disguised Adware Infect 9 Million Google Play Users
We recently discovered an active adware family (detected by Trend Micro as AndroidOS_HidenAd) disguised as 85 game, TV, and remote control simulator apps on the Google Play
store.
By: Ecular Xu
Jan 08, 2019
Read time: 3 min (854 words)

Adware is bothersome, disruptive, and have been around for a long time, but they're still around.
In fact, we recently discovered an active adware family (detected by Trend Micro as
AndroidOS_HidenAd) disguised as 85 game, TV, and remote control simulator apps on the
Google Play store. This a

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

[Page 1]
Malware
Disguised Adware Infect 9 Million Google Play Users
We recently discovered an active adware family (detected by Trend Micro as AndroidOS_HidenAd) disguised as 85 game, TV, and remote control simulator apps on the Google Play
store.
By: Ecular Xu
Jan 08, 2019

### 3.6 广告欺诈 (**MEDIUM**)

[Page 1]
Malware
Disguised Adware Infect 9 Million Google Play Users
We recently discovered an active adware family (detected by Trend Micro as AndroidOS_HidenAd) disguised as 85 game, TV, and remote control simulator apps on the Google Play
store.
By: Ecular Xu

[Page 21]
Figure 6. A screen capture of a full-screen ad that pops up after clicking the call to action button
on one of the fake apps
After the user exits the full-screen ad, more buttons that provide app-related options for users
appear on the screen. It also prompts the user to give the app a five-star rating on Google Play. If

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等) |
| **综合风险** | **CRITICAL** | 检测到2类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): config_update
2. **广告欺诈** (MEDIUM): 发现
