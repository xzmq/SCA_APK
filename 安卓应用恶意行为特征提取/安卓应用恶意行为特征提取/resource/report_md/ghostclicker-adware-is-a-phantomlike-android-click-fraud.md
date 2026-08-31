# GhostClicker Adware: a Phantomlike Android Click Fraud - 分析报告

> **来源**: Trend Micro
> **发布日期**: Aug 16, 2017
> **作者**: Echo Duan
> **恶意软件名称**: GhostClicker Adware: a Phantomlike Android Click Fraud
> **厂商检测名**: `Trend Micro detects these`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 日本, 俄罗斯, 亚洲, 巴西
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Mobile
GhostClicker Adware: a Phantomlike Android Click Fraud
We’ve uncovered a pervasive auto-clicking adware from as much as 340 apps from Google Play, one of which, named “Aladdin’s Adventure’s World”, was downloaded 5 million times.
Our detections/sensors saw the prevalence of this adware in Southeast Asia.
By: Echo Duan, Roland Sun
Aug 16, 2017
Read time: 4 min (1034 words)
We’ve uncovered a pervasive auto-clicking adware from as much as 340 apps from Google Play,
one of which, named “Aladdin’s Adventure’s World”, was downloaded 5 million times. These
adware-embedded applications

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: account

GhostClicker is actually an earlier version of itself
We hunted GhostClicker’s trail and found that it was an earlier iteration of itself. A later version
removed the auto-click feature and device administration permission request, likely to make the
adware stealthier. After the user unlocks the screen, the adware will pop up interstitial
advertisements at certain intervals if the device is connected to a network with data . We
encountered this version of GhostClicker in Aladdin’s Adventure’s World.
Retracing the adware’s timeline, we also saw that apps embedded with GhostClicker were

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

clicking. Indeed, it’s true to its moniker: ghosting over the device’s screen to click ads.
To earn more revenue, GhostClicker generates fake traffic. It will pop up in other apps’ download
links in Google Store or open a YouTube video link in the device’s browser via communication
with its command and control (C&C) server. Upon activation of device administration,
GhostClicker will execute those auto-clicks every minute.

[Page 10]

clicking. Indeed, it’s true to its moniker: ghosting over the device’s screen to click ads.
To earn more revenue, GhostClicker generates fake traffic. It will pop up in other apps’ download
links in Google Store or open a YouTube video link in the device’s browser via communication
with its command and control (C&C) server. Upon activation of device administration,
GhostClicker will execute those auto-clicks every minute.

[Page 10]

clicking. Indeed, it’s true to its moniker: ghosting over the device’s screen to click ads.
To earn more revenue, GhostClicker generates fake traffic. It will pop up in other apps’ download
links in Google Store or open a YouTube video link in the device’s browser via communication
with its command and control (C&C) server. Upon activation of device administration,
GhostClicker will execute those auto-clicks every minute.

[Page 10]

### 3.4 C2 反检测 (**HIGH**)

The adware comes with a few requirements. Once launched, the affected app will retrieve the
device’s system property (http.agent), which is used to configure the User-Agent string in
Android devices. If the string contains “nexus”, GhostClicker’s routines will not be triggered. We
construe this routine as a way to evade sandboxes like Android’s built-in Android Application
Sandbox, as Android emulators/sandboxing environments are usually named “Nexus XXX”.
Figure 3. GhostClicker triggering its routines when the device’s http.agent doesn’t contain “nexus”
Some of the GhostClicker-embedded apps we analyzed also requested device administration

### 3.6 广告欺诈 (**MEDIUM**)

[Page 1]
Mobile
GhostClicker Adware: a Phantomlike Android Click Fraud
We’ve uncovered a pervasive auto-clicking adware from as much as 340 apps from Google Play, one of which, named “Aladdin’s Adventure’s World”, was downloaded 5 million times.
Our detections/sensors saw the prevalence of this adware in Southeast Asia.
By: Echo Duan, Roland Sun

[Page 1]
Mobile
GhostClicker Adware: a Phantomlike Android Click Fraud
We’ve uncovered a pervasive auto-clicking adware from as much as 340 apps from Google Play, one of which, named “Aladdin’s Adventure’s World”, was downloaded 5 million times.
Our detections/sensors saw the prevalence of this adware in Southeast Asia.
By: Echo Duan, Roland Sun

[Page 1]
Mobile
GhostClicker Adware: a Phantomlike Android Click Fraud
We’ve uncovered a pervasive auto-clicking adware from as much as 340 apps from Google Play, one of which, named “Aladdin’s Adventure’s World”, was downloaded 5 million times.
Our detections/sensors saw the prevalence of this adware in Southeast Asia.
By: Echo Duan, Roland Sun

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
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): account
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): 发现
4. **广告欺诈** (MEDIUM): 发现
