# First-of-its-kind spyware sneaks into - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: First-of-its-kind spyware sneaks into
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
ESET Research
First-of-its-kind spyware sneaks into
Google Play
ESET analysis breaks down the first known spyware that is built on the AhMyth open-source
espionage tool and has appeared on Google Play – twice
Lukas Stefanko
22 Aug 2019 • 5 min. read
[Page 2]
ESET researchers have discovered the first known spyware that is built on the foundations of
AhMyth open-source malware and has circumvented Google’s app-vetting process. The malicious
app, called Radio Balouch aka RB Music, is actually a fully working streaming radio app for Balouchi
music enthusiasts, except that it comes with a

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

ESET researchers have discovered the first known spyware that is built on the foundations of
AhMyth open-source malware and has circumvented Google’s app-vetting process. The malicious
app, called Radio Balouch aka RB Music, is actually a fully working streaming radio app for Balouchi
music enthusiasts, except that it comes with a major sting in its tail – stealing personal data of its
users. The app snuck into the official Android app store twice, but was swiftly removed by Google
both times after we alerted the company to it.
AhMyth, the open-source Remote Access Tool from which the Radio Balouch app borrowed its

The malicious Radio Balouch app works on Android 4.2 and above. Its internet radio functionality is
bundled with the functionality of AhMyth into one malicious app.
After installation, the internet radio component is fully functional, playing a stream of Balouchi
music. However, the added malicious functionality enables the app to steal contacts, harvest files
stored on the device and send SMS messages from the affected device.
Functionality for stealing SMS messages stored on the device is also present. However, this
functionality can’t be utilized since Google’s recent restrictions only allow the default SMS app to

### 3.2 远程控制 (**CRITICAL**)

After being removed from Google Play, the malicious radio app is only available on third-party app
stores at the time of writing. It has also been distributed from a dedicated website,
radiobalouch[.]com, via a link promoted via a related Instagram account. This server was also used
for the spyware’s C&C communications (see below). The domain was registered on March 30th,
2019, and shortly after our complaint, the website was down and still is at the time of writing.
The attackers’ Instagram account still, at the time of writing, serves a link to the app that has been
removed from Google Play. They have also set up a YouTube channel with one video introducing

### 3.4 C2 反检测 (**HIGH**)

“logined” state, in the operators’ poor English. Probably, this step has been added to lure credentials
from the victims and try to break into other services using the obtained passwords – a reminder to
never reuse passwords across services. On a side note: the credentials are transmitted
unencrypted, over an HTTP connection.
Figure 4. Radio Balouch app’s Home (left) and Settings (right) screens

[Page 7]

### 3.7 蠕虫传播 (**HIGH**)

bundled with the functionality of AhMyth into one malicious app.
After installation, the internet radio component is fully functional, playing a stream of Balouchi
music. However, the added malicious functionality enables the app to steal contacts, harvest files
stored on the device and send SMS messages from the affected device.
Functionality for stealing SMS messages stored on the device is also present. However, this
functionality can’t be utilized since Google’s recent restrictions only allow the default SMS app to
access those messages.

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): 发现
3. **C2 反检测** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
