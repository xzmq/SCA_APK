# APT & Targeted Attacks - 分析报告

> **来源**: Trend Micro
> **发布日期**: May 08, 2018
> **作者**: Ecular Xu
> **恶意软件名称**: APT & Targeted Attacks
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播, 蓝牙/U盘传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
APT & Targeted Attacks
Windows, Android Users Targeted by Maikspy Spyware
We discovered a malware family called Maikspy — a multi-platform spyware that can steal users’ private data. The spyware targets Windows and Android users, and first posed as an
adult game named after a popular U.S.-based adult film actress.
By: Ecular Xu, Grey Guo
May 08, 2018
Read time: 8 min (2065 words)
We discovered a malware family called Maikspy — a multi-platform spyware that can steal users’
private data. The spyware targets Windows and Android users, and first posed as an adult game
named after a popul

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account, clipboard

[Page 1]
APT & Targeted Attacks
Windows, Android Users Targeted by Maikspy Spyware
We discovered a malware family called Maikspy — a multi-platform spyware that can steal users’ private data. The spyware targets Windows and Android users, and first posed as an
adult game named after a popular U.S.-based adult film actress.
By: Ecular Xu, Grey Guo
May 08, 2018

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

name of the adult film actress and spyware, has been around since 2016.
Our analysis of the latest Maikspy variants revealed that users contracted the spyware from
hxxp://miakhalifagame[.]com/, a website that distributes malicious apps (including the 2016
adult game) and connects to its C&C server to upload data from infected devices and machines.
Multiple Twitter handles were found promoting the adult game called Virtual Girlfriend and
sharing the malicious domain via short links.

The stolen information will be either written into .txt or .csv formats before being uploaded to
the C&C server. After fetching and uploading the abovementioned stolen data, the malicious app

will check the command (CMD) from the C&C server every 60 seconds. The following are the
supported commands:
CMD Details

### 3.6 广告欺诈 (**MEDIUM**)

Figure 7. Infection chain of Maikspy Windows variant

[Page 10]
Figure 8. These buttons greeted users who clicked the Twitter short link of
hxxp://miakhalifagame[.]com/
In the case of the Windows variant (WORM_INFOKEY.A) of Maikspy last seen in April 2017, the
user will be tricked into downloading a MiaKhalifa.rar file, which contains the files seen in the

### 3.7 蠕虫传播 (**HIGH**)

[Page 10]
Figure 8. These buttons greeted users who clicked the Twitter short link of
hxxp://miakhalifagame[.]com/
In the case of the Windows variant (WORM_INFOKEY.A) of Maikspy last seen in April 2017, the
user will be tricked into downloading a MiaKhalifa.rar file, which contains the files seen in the
screenshot below:

Meanwhile, the first Android variant of this spyware family appeared in January 2017. It was also
under the guise of the previously mentioned adult game and still connects to the
aforementioned C&C server. It was capable of recording phone calls and stealing information
such as the device’s location, SMS, contacts, WhatsApp database, and record sound around the
affected device. The next variant appeared quickly, and it added the following abilities to its
routines: Steal information about the device’s clipboard, phone number, installed app list, and
accounts. Meanwhile, the ability to steal the WhatsApp database was removed. It also changed

Steal contacts

Steal SMS

The stolen information will be either written into .txt or .csv formats before being uploaded to
the C&C server. After fetching and uploading the abovementioned stolen data, the malicious app

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播, 蓝牙/U盘传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): config_update
3. **广告欺诈** (MEDIUM): 发现
4. **蠕虫传播** (HIGH): 发现
