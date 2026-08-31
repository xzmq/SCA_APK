# Project Spy – A Spyware - 分析报告

> **来源**: Trend Micro
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Project Spy – A Spyware
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯, 伊朗
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
gbhackers.
Malware
Project Spy – A Spyware
Campaign That Hack
Android & iOS Devices via
Coronavirus Update App
ByBalaji April 17, 2020

[Page 2]
Researchersg disbcovheread ac nekw ecybrerses.pionage campaign named
Project Spy through which hackers targeting Android and iOS devices
with spyware using Coronavirus Update App.
Cybercriminals taking advantage of the currently ongoing COVID-19
pandemic as a lure and lunching a fake Coronavirus updates App
and install spyware on the victim’s devices.
We have reported several ongoing malware and phishing
campaigns related to Coronavirus pand

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account, device_info

Researchers observed this mobile spyware campaign at the end of
the March, and the Corna virus update app masquerading and
tempt users to download and install it on their device.
The Project Spy has installed with various data-stealing capabilities
that include capable of stealing messages from popular messaging
apps by gaining permission from the users.
It also requests permission to access the storage and abusing

### 3.2 远程控制 (**CRITICAL**)

You can follow us on Linkedin, Twitter, Facebook for daily
Cybersecurity and hacking news updates.
Indicators of Compromise
e394e53e53cd9047d6cff184ac333ef7698a34b777ae3aac82c2c669
ef661dfe
e8d4713e43241ab09d40c2ae8814302f77de76650ccf3e7db83b3ac8
ad41f9fa

### 3.7 蠕虫传播 (**HIGH**)

[Page 3]
There are folglowbingh daata ccollkecteionr asctiv.ities are observed:-
Upload GSM, WhatsApp, Telegram, Facebook, and Threema messages
Upload voice notes, contacts stored, accounts, call logs, location
information, and images
Upload the expanded list of collected device information (e.g., IMEI,

Collect device and system information (i.e., IMEI, device ID, manufacturer,
model and phone number), location information, contacts stored, and call
logs
Collect and send SMS
Take pictures via the camera
Upload recorded MP4 files
Monitor calls

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到3类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): 发现
3. **蠕虫传播** (HIGH): 发现
