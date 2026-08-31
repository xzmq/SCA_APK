# [Page 1] - 分析报告

> **来源**: Trend Micro
> **发布日期**: since 2018
> **作者**: Jessie Huang
> **恶意软件名称**: [Page 1]
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 欧洲, 亚洲
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
We've moved! Get the latest research, news and perspectives See it now>
Trend Micro
About TrendLabs Security Intelligence Blog
Search:
Go to…
Home
Categories
Home » Mobile » Adware Campaign Identified From 182 Game and Camera Apps on Google Play and Third-Party Stores Like
9Apps
Adware Campaign Identified From 182 Game and Camera
Apps on Google Play and Third-Party Stores Like 9Apps
Posted on:July 1, 2019 at 5:00 am
Posted in:Mobile
Author:
Trend Micro
0
By: Jessie Huang (Mobile Threats Analyst)
As mobile ad spending increases year by year — the projected mobile ad spend for U.S. adve

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: account

Users can manually remove the adware-hosted fake apps using the steps shown below. But it can prove to be an annoying task
when the full-screen ads show every after five minutes, as seen in some of the malicious apps.
Cybercriminals are finding new ways to make mobile threats more surreptitious and evasive to profit from users, not just by
deploying adware but even by stealing sensitive information. This is why mobile devices should have comprehensive security and
software program against mobile malware.
The Trend Micro™ Mobile Security for Android™ (also available on Google Play) solution blocks malicious apps, and end users can
also benefit from its multilayered security capabilities that secure the device owner’s data and privacy and that safeguard them

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

Figure 12. Screen capture of code that details conditions that would determine whether the app will hide itself from the user’s
screen or otherwise
Figure 13. Screen capture of code that features a filter with a predefined referrer source
Figure 14. Screen capture of code that controls the app’s behavior in connecting to the adware variant’s C&C server
Because of the lengthy delay time before any malicious activity is deployed in the app, connecting to the C&C server is also
postponed, allowing the adware to run without being flagged by a device’s AV solutions and analysis tools. The adware variant
also evades the static analysis of AV solutions via the encoded hide method setComponentEnabledSetting.

Figure 12. Screen capture of code that details conditions that would determine whether the app will hide itself from the user’s
screen or otherwise
Figure 13. Screen capture of code that features a filter with a predefined referrer source
Figure 14. Screen capture of code that controls the app’s behavior in connecting to the adware variant’s C&C server
Because of the lengthy delay time before any malicious activity is deployed in the app, connecting to the C&C server is also
postponed, allowing the adware to run without being flagged by a device’s AV solutions and analysis tools. The adware variant
also evades the static analysis of AV solutions via the encoded hide method setComponentEnabledSetting.

### 3.4 C2 反检测 (**HIGH**)

Figure 14. Screen capture of code that controls the app’s behavior in connecting to the adware variant’s C&C server
Because of the lengthy delay time before any malicious activity is deployed in the app, connecting to the C&C server is also
postponed, allowing the adware to run without being flagged by a device’s AV solutions and analysis tools. The adware variant
also evades the static analysis of AV solutions via the encoded hide method setComponentEnabledSetting.

[Page 7]
We've moved! Get the latest research, news and perspectives See it now>

### 3.5 勒索软件 (**HIGH**)

software program against mobile malware.
The Trend Micro™ Mobile Security for Android™ (also available on Google Play) solution blocks malicious apps, and end users can
also benefit from its multilayered security capabilities that secure the device owner’s data and privacy and that safeguard them
from ransomware, fraudulent websites, and identity theft.
For organizations, the Trend Micro™ Mobile Security for Enterprise suite provides device, compliance and application management,
data protection, and configuration provisioning, as well as protects devices from attacks that leverage vulnerabilities, preventing
unauthorized access to apps and detecting and blocking malware and fraudulent websites. Trend Micro’s Mobile App Reputation

### 3.6 广告欺诈 (**MEDIUM**)

Go to…
Home
Categories
Home » Mobile » Adware Campaign Identified From 182 Game and Camera Apps on Google Play and Third-Party Stores Like
9Apps
Adware Campaign Identified From 182 Game and Camera
Apps on Google Play and Third-Party Stores Like 9Apps

We've moved! Get the latest research, news and perspectives See it now>
Figure 7. Screen capture of code showing the filter “android.intent.action.USER_PRESENT” and the ad time and count limits
Even when the app is not running, full-screen ads that cannot be immediately closed or exited pop-up on a user’s screen. When a
user attempts to promptly close an ad that has popped up by clicking the Back button, it will only show an “open with” call-to-
action message instead of exiting out of the ad. This adds to the cybercriminal’s mobile ad revenue and to the user’s annoyance.
The button to close the ad will appear only after a set number of seconds has elapsed.
The infected device’s battery and memory will also be consumed as ads continue to pop-up from the background.

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `android.intent.action.USER_PRESENT` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): account
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): 发现
4. **勒索软件** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
