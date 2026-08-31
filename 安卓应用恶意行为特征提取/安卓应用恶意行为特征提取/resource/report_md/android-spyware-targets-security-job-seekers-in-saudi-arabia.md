# Android Spyware Targets Security Job Seekers in - 分析报告

> **来源**: McAfee
> **发布日期**: MAY 31, 2016
> **作者**: Anuradha
> **恶意软件名称**: Android Spyware Targets Security Job Seekers in
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 日本, 美国
| 活动时间 | 未知
| 传播方式 | 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Android Spyware Targets Security Job Seekers in
Saudi Arabia
Yukihiro Okutomi MAY 31, 2016 4 MIN READ
The Middle East is the new Wild West of mobile malware, especially for targeted attacks
and intelligence gathering campaigns. During the past few years, McAfee Mobile
Research has monitored and reported on several countries in the region and has found
an alarming increase in campaigns using mobile malware for not only disruption and
hacktivism but also for intelligence gathering. Today we shed light on a new campaign
targeting Saudi Arabia.
We have identified a campaign that is workin

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, device_info

Products Features Resources About Us Why McAfee Support Log in

Topics At McAfee English
The spyware, Android/ChatSpy, was distributed as a private chat application. It steals
user contacts, SMS messages, and voice calls from infected devices and forwards them
to the attacker’s server, which is in the same location as the job site.
20160527-

### 3.2 远程控制 (**CRITICAL**)

data loss. For more information about McAfee Mobile Security, visit
http://www.mcafeemobilesecurity.com.
SHA-256 hash of analyzed sample(s):
7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb
4aef8d9a3c4cc1e66a6f2c6355ecc38d87d9c81bb2368f4ca07b2a02d2e4923b
Control server:
hxxp://ksa-sef[dot]com/Hack%20Mobaile/

SHA-256 hash of analyzed sample(s):
7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb
4aef8d9a3c4cc1e66a6f2c6355ecc38d87d9c81bb2368f4ca07b2a02d2e4923b
Control server:
hxxp://ksa-sef[dot]com/Hack%20Mobaile/
Introducing McAfee+
Identity theft protection and privacy for your digital life

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

Products Features Resources About Us Why McAfee Support Log in

Topics At McAfee English
Learn to Identify and Astaroth: Banking Android Malware Think Before You Android M
Avoid Malicious Trojan Abusing Promises Energy Click: EPI PDF’s Hidden Targets In
Browser Extensions GitHub for Resilience Subsidy to Steal Extras Banking U
In this guide, you will learn by Harshil Patel and FAuinthaonrecdi ably DZeaPteang Chen Authored by: Anuradha & FAuinthaonrecdi ably I

Products Features Resources About Us Why McAfee Support Log in

Topics At McAfee English
Learn to Identify and Astaroth: Banking Android Malware Think Before You Android M
Avoid Malicious Trojan Abusing Promises Energy Click: EPI PDF’s Hidden Targets In
Browser Extensions GitHub for Resilience Subsidy to Steal Extras Banking U
In this guide, you will learn by Harshil Patel and FAuinthaonrecdi ably DZeaPteang Chen Authored by: Anuradha & FAuinthaonrecdi ably I

### 3.6 广告欺诈 (**MEDIUM**)

Topics At McAfee English
Learn to Identify and Astaroth: Banking Android Malware Think Before You Android M
Avoid Malicious Trojan Abusing Promises Energy Click: EPI PDF’s Hidden Targets In
Browser Extensions GitHub for Resilience Subsidy to Steal Extras Banking U
In this guide, you will learn by Harshil Patel and FAuinthaonrecdi ably DZeaPteang Chen Authored by: Anuradha & FAuinthaonrecdi ably I
about the advantages and Prabudh Chakravorty Recently, we identified an Prabudh PDF converting MMciAnfeee C’sr Myopb

### 3.7 蠕虫传播 (**HIGH**)

Topics At McAfee English
The spyware, Android/ChatSpy, was distributed as a private chat application. It steals
user contacts, SMS messages, and voice calls from infected devices and forwards them
to the attacker’s server, which is in the same location as the job site.
20160527-
icon

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `www.mcafeemobilesecurity.com` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `4aef8d9a3c4cc1e66a6f2c6355ecc38d87d9c81bb2368f4ca07b2a02d2e4923b` | 恶意文件 |
| `7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb` | 恶意文件 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `http://www.mcafeemobilesecurity.com` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing
4. **广告欺诈** (MEDIUM): 发现
5. **蠕虫传播** (HIGH): 发现
