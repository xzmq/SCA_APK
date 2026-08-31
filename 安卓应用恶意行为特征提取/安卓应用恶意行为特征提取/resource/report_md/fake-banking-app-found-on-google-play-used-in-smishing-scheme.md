# scheme targeting Spanish-speaking users. - 分析报告

> **来源**: Trend Micro
> **发布日期**: Nov 07, 2018
> **作者**: Echo Duan
Nov
> **恶意软件名称**: scheme targeting Spanish-speaking users.
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), SMiShing (短信钓鱼)
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Malware
Fake Banking App Found on Google Play Used in SMiShing
As users start to look for apps and other services from their banks, opportunities for scammers also increase. One recent example of this is the app Movil Secure, part of a SMiShing
scheme targeting Spanish-speaking users.
By: Echo Duan
Nov 07, 2018
Read time: 3 min (817 words)
Banks are offering more features and upgrades for their banking apps, and thanks to their
convenience more users are adopting mobile banking services around the world. But as new
financial technology proliferates and users start to look for apps and

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

299e1eb8a1f13e1eb77a1c38e5cf7bbdc588db89d4eaad91e7fc95d156d986e5

24e7a8ed726efa463edec2e19ad4796cf4b97755b8fdf06dea4950c175c01f77

C&C:

app published on Google Play.
What the app does and how it affects victims
When the app first launches, it gathers device identifiers: device ID, OS version, and Country
Code. Then it sends all the information to its command and control (C&C) server. It also hides
itself from the user’s view — there is no icon on the mobile phone screen.

[Page 5]

app published on Google Play.
What the app does and how it affects victims
When the app first launches, it gathers device identifiers: device ID, OS version, and Country
Code. Then it sends all the information to its command and control (C&C) server. It also hides
itself from the user’s view — there is no icon on the mobile phone screen.

[Page 5]

app published on Google Play.
What the app does and how it affects victims
When the app first launches, it gathers device identifiers: device ID, OS version, and Country
Code. Then it sends all the information to its command and control (C&C) server. It also hides
itself from the user’s view — there is no icon on the mobile phone screen.

[Page 5]

### 3.3 银行木马 (**CRITICAL**)

[Page 1]
Malware
Fake Banking App Found on Google Play Used in SMiShing
As users start to look for apps and other services from their banks, opportunities for scammers also increase. One recent example of this is the app Movil Secure, part of a SMiShing
scheme targeting Spanish-speaking users.
By: Echo Duan

[Page 1]
Malware
Fake Banking App Found on Google Play Used in SMiShing
As users start to look for apps and other services from their banks, opportunities for scammers also increase. One recent example of this is the app Movil Secure, part of a SMiShing
scheme targeting Spanish-speaking users.
By: Echo Duan

### 3.7 蠕虫传播 (**HIGH**)

Figure 3. Sign-in page for command and control server

[Page 6]
The data it collects isn't limited to device identifiers. The app also collects SMS messages and
phone numbers; analyzing the code of this app shows that this is the main goal of this spyware.
As seen below (in Figure 4), when a device with the app installed receives a new SMS, it sends the
SMS sender and message content to the C&C server and a specific phone number. This type of

---

## 4. IoCs (威胁指标)

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `24e7a8ed726efa463edec2e19ad4796cf4b97755b8fdf06dea4950c175c01f77` | 恶意文件 |
| `299e1eb8a1f13e1eb77a1c38e5cf7bbdc588db89d4eaad91e7fc95d156d986e5` | 恶意文件 |
| `b168e64a02c3aed52b0c6f77a380420dd2495c3440c85a3b7ed99b8ac871d46a` | 恶意文件 |
| `d8018d869254abd6e0b2fb33631fcc56c9f2e355c5d6f40701f71c1a73331cb3` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), SMiShing (短信钓鱼) |
| **综合风险** | **CRITICAL** | 检测到3类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **银行木马** (CRITICAL): 发现
3. **蠕虫传播** (HIGH): 发现
