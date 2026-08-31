# Android Computer Security Cyber Security - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Android Computer Security Cyber Security
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
gbhackers.
Android Computer Security Cyber Security
Hackers Spread Android
Malware Via Coronavirus
Safety App & Gain Contacts
Access to Infect All of Them
via SMS
ByBalaji March 21, 2020

[Page 2]
Researchersg disbcovheread ac nekw eCorronsav.irus safety Android App that
infects Android users via malware, as a result, it hefty usage charges
for victims.
Attackers taking advantage of the Coronavirus fear to continuously
exploit online users by infecting their mobile with various tactics and
techniques.
An App called “Corona Safety Mask” that is spread via the malicious
domain ” hxxp:/

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts

After the app gets installed, users to click a button that leads to an
online portal where users can buy the Masks.
Users ask to pay online to purchase the mask, in the background,
attackers steal the credit/debit card information.
According to the Zscalar research “Along with all the above
activities, an important functionality takes place behind the
scenes. The app checks whether it has already sent SMS

### 3.3 银行木马 (**CRITICAL**)

stages and this (and other) functionalities will be added as the app
is updated.
Also Read: Beware of Android Coronavirus Tracker app that Lock’s
Your Device & Asks Ransom Payment


### 3.5 勒索软件 (**HIGH**)

stages and this (and other) functionalities will be added as the app
is updated.
Also Read: Beware of Android Coronavirus Tracker app that Lock’s
Your Device & Asks Ransom Payment


### 3.6 广告欺诈 (**MEDIUM**)

[Page 3]
gbhackers.
After the app gets installed, users to click a button that leads to an
online portal where users can buy the Masks.
Users ask to pay online to purchase the mask, in the background,
attackers steal the credit/debit card information.

### 3.7 蠕虫传播 (**HIGH**)

[Page 1]
gbhackers.
Android Computer Security Cyber Security
Hackers Spread Android
Malware Via Coronavirus
Safety App & Gain Contacts
Access to Infect All of Them

Malware Via Coronavirus
Safety App & Gain Contacts
Access to Infect All of Them
via SMS
ByBalaji March 21, 2020


---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.coronasafetymask.app` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts
2. **银行木马** (CRITICAL): 发现
3. **勒索软件** (HIGH): 发现
4. **广告欺诈** (MEDIUM): 发现
5. **蠕虫传播** (HIGH): 发现
