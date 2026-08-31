# UPDATED: Simplocker ransomware: - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: UPDATED: Simplocker ransomware:
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 俄罗斯
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
ESET Research
UPDATED: Simplocker ransomware:
New variants spread by Android
downloader apps
ESET LiveGrid® telemetry has indicated several new infection vectors used by
Android/Simplocker. The “typical” ones revolve around internet porn, or popular games like
Grand Theft Auto: San Andreas.
Robert Lipovsky
25 Jun 2014 • 3 min. read
[Page 2]
UPDATE: Our developers have created ESET Simplocker Decryptor, an easy-to-use tool to
decrypt files that have been encrypted by Simplocker.
To install the application, please download it from Virus Radar with your device or scan the
QR code below. 

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

[Page 3]
Since our initial discovery of Android/Simplocker we have observed several different variants. The
differences between them are mostly in:
Tor usage – some use a Tor .onion domain, whereas others use a more conventional C&C domain.
Different ways of receiving the “decrypt” command, indicating that the ransom has been paid.
Different nag screens, different ransoms (and different currencies as well – we’ve seen Ukrainian hryvnias as
well as Russian rubles).

Since our initial discovery of Android/Simplocker we have observed several different variants. The
differences between them are mostly in:
Tor usage – some use a Tor .onion domain, whereas others use a more conventional C&C domain.
Different ways of receiving the “decrypt” command, indicating that the ransom has been paid.
Different nag screens, different ransoms (and different currencies as well – we’ve seen Ukrainian hryvnias as
well as Russian rubles).
Use of imagery – some display a photo of the victim taken with the phone’s camera to increase the

user who scrutinizes app permissions at installation may allow this one
Furthermore, in the example we’ve analyzed, the URL contained within the app didn’t point to the
malicious Simplocker APK package directly. Instead, the trojan was served after a redirect from the
server under the attacker’s control. This technique is something to watch out for.
The described trojan-downloader was masquerading as a legitimate app called USSDDualWidget.
Figure 5 - Trojan-downloader posing as legitimate USSDDualWidget appSHA1 hash

### 3.4 C2 反检测 (**HIGH**)

[Page 2]
UPDATE: Our developers have created ESET Simplocker Decryptor, an easy-to-use tool to
decrypt files that have been encrypted by Simplocker.
To install the application, please download it from Virus Radar with your device or scan the
QR code below. To install the app, you must allow installation from Unknown Sources
(Settings -> Security -> Unknown Sources).

### 3.5 勒索软件 (**HIGH**)

[Page 1]
ESET Research
UPDATED: Simplocker ransomware:
New variants spread by Android
downloader apps
ESET LiveGrid® telemetry has indicated several new infection vectors used by

### 3.7 蠕虫传播 (**HIGH**)

[Page 1]
ESET Research
UPDATED: Simplocker ransomware:
New variants spread by Android
downloader apps
ESET LiveGrid® telemetry has indicated several new infection vectors used by
Android/Simplocker. The “typical” ones revolve around internet porn, or popular games like

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **C2 反检测** (HIGH): 发现
3. **勒索软件** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
