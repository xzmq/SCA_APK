# Mobile Campaign ‘Bouncing Golf’ Affects Middle East - 分析报告

> **来源**: Trend Micro
> **发布日期**: Jun 18, 2019
> **作者**: Ecular Xu
> **恶意软件名称**: Mobile Campaign ‘Bouncing Golf’ Affects Middle East
> **厂商检测名**: `Trend Micro detects as`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Mobile
Mobile Campaign ‘Bouncing Golf’ Affects Middle East
We uncovered a cyberespionage campaign targeting Middle Eastern countries. We named this campaign “Bouncing Golf” based on the malware’s code in the package named “golf.”
By: Ecular Xu, Grey Guo
Jun 18, 2019
Read time: 5 min (1348 words)
We uncovered a cyberespionage campaign targeting Middle Eastern countries. We named this
campaign “Bouncing Golf” based on the malware’s code in the package named “golf.” The
malware involved, which Trend Micro detects as AndroidOS_GolfSpy.HRX, is notable for its wide
range of cyberespionage c

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account, clipboard

[Page 3]
GolfSpy's Potential Impact
Given GolfSpy’s information-stealing capabilities, this malware can effectively hijack an infected
Android device. Here is a list of information that GolfSpy steals:
Device accounts

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

campaign “Bouncing Golf” based on the malware’s code in the package named “golf.” The
malware involved, which Trend Micro detects as AndroidOS_GolfSpy.HRX, is notable for its wide
range of cyberespionage capabilities. Malicious codes are embedded in apps that the operators
repackaged from legitimate applications. Monitoring the command and control (C&C) servers
used by Bouncing Golf, we’ve so far observed more than 660 Android devices infected with
GolfSpy. Much of the information being stolen appear to be military-related.
The campaign’s attack vector is also interesting. These repackaged, malware-laden apps are

campaign “Bouncing Golf” based on the malware’s code in the package named “golf.” The
malware involved, which Trend Micro detects as AndroidOS_GolfSpy.HRX, is notable for its wide
range of cyberespionage capabilities. Malicious codes are embedded in apps that the operators
repackaged from legitimate applications. Monitoring the command and control (C&C) servers
used by Bouncing Golf, we’ve so far observed more than 660 Android devices infected with
GolfSpy. Much of the information being stolen appear to be military-related.
The campaign’s attack vector is also interesting. These repackaged, malware-laden apps are

campaign “Bouncing Golf” based on the malware’s code in the package named “golf.” The
malware involved, which Trend Micro detects as AndroidOS_GolfSpy.HRX, is notable for its wide
range of cyberespionage capabilities. Malicious codes are embedded in apps that the operators
repackaged from legitimate applications. Monitoring the command and control (C&C) servers
used by Bouncing Golf, we’ve so far observed more than 660 Android devices infected with
GolfSpy. Much of the information being stolen appear to be military-related.
The campaign’s attack vector is also interesting. These repackaged, malware-laden apps are

### 3.4 C2 反检测 (**HIGH**)

phone call. It will also take a photo using the device’s front camera when the user wakes the
device.
Apart from collecting the above data, the spyware monitors users’ phone calls, records them,
and saves the recorded file on the device. GolfSpy encrypts all the stolen data using a simple
XOR operation with a pre-configured key before sending it to the C&C server using the HTTP
POST method.
Figure 5. Code snippets showing how GolfSpy monitors phone calls via register receiver (top left),

### 3.7 蠕虫传播 (**HIGH**)

Sensor information

SMS messages

Pictures

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
