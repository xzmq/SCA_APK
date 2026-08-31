# XLoader Android Spyware and Banking Trojan Distributed via DNS - 分析报告

> **来源**: Trend Micro
> **发布日期**: Apr 20, 2018
> **作者**: Trend Micro
Apr
> **恶意软件名称**: XLoader Android Spyware and Banking Trojan Distributed via DNS
> **厂商检测名**: `Trend Micro detects these`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 日本, 韩国, 中国
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, DNS 欺骗
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

attack chain involves diverting internet traffic to
attacker-specified domains by compromising and overwriting the router’s DNS settings. A fake
alert will notify and urge the user to access the malicious domain and download XLoader.

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

these as ANDROIDOS_XLOADER.HRX.
These malware pose as legitimate Facebook or Chrome applications. They are distributed from
polluted DNS domains that send a notification to an unknowing victim’s device. The malicious
apps can steal personally identifiable and financial data and install additional apps. XLoader can

also hijack the infected device (i.e., send SMSs) and sports self-protection/persistence
mechanisms through device administrator privileges.

[Page 12]
The abuse of the WebSocket protocol provides XLoader with a persistent connection between
clients and servers where data can be transported any time. XLoader abuses the MessagePack
(a data interchange format) to package the stolen data and exfiltrate it via the WebSocket
protocol for faster and more efficient transmission.
Figure 8. Screenshot showing one of the web pages with hidden C&C-related URL

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

and game development companies. XLoader also prevents victims from accessing the device’s
settings or using a known antivirus (AV) app in the country.
XLoader can also load multiple malicious modules to receive and execute commands from its
remote command-and-control (C&C) server, as shown below:

Figure 7. Screenshot showing XLoader’s malicious modules
Here’s a list of the modules and their functions:

E3626BF6
17D1415176121AFF8C0020
C3A094B3D72F9802F5145 gfdg.qwe.gsdg Facebook
C80EBCA47DCFE10CC21F6
1849E8DFD9D1C03DBE6C
1464F9B05492012A6C14A0 jfgh.rtw.ghm Facebook
A5B63FEB938F1C8B70309B

and game development companies. XLoader also prevents victims from accessing the device’s
settings or using a known antivirus (AV) app in the country.
XLoader can also load multiple malicious modules to receive and execute commands from its
remote command-and-control (C&C) server, as shown below:

Figure 7. Screenshot showing XLoader’s malicious modules
Here’s a list of the modules and their functions:

We reverse engineered XLoader and found that it appears to target South Korea-based banks
and game development companies. XLoader also prevents victims from accessing the device’s
settings or using a known antivirus (AV) app in the country.
XLoader can also load multiple malicious modules to receive and execute commands from its
remote command-and-control (C&C) server, as shown below:

Figure 7. Screenshot showing XLoader’s malicious modules

and game development companies. XLoader also prevents victims from accessing the device’s
settings or using a known antivirus (AV) app in the country.
XLoader can also load multiple malicious modules to receive and execute commands from its
remote command-and-control (C&C) server, as shown below:

Figure 7. Screenshot showing XLoader’s malicious modules
Here’s a list of the modules and their functions:

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: app_replace, phishing

[Page 1]
Mobile
XLoader Android Spyware and Banking Trojan Distributed via DNS
Spoofing
We have been detecting a new wave of network attacks since early March, which, for now, are targeting Japan, Korea, China, Taiwan, and Hong Kong. Trend Micro detects these as
ANDROIDOS_XLOADER.HRX.

[Page 1]
Mobile
XLoader Android Spyware and Banking Trojan Distributed via DNS
Spoofing
We have been detecting a new wave of network attacks since early March, which, for now, are targeting Japan, Korea, China, Taiwan, and Hong Kong. Trend Micro detects these as
ANDROIDOS_XLOADER.HRX.

### 3.4 C2 反检测 (**HIGH**)

Figure 3. Screenshot of the fake notification on a spoofed/poisoned domain

Technical Analysis
XLoader first loads the encrypted payload from Assets/db as test.dex to drop the necessary
modules then requests for device administrator privileges. Once granted permission, it hides its

[Page 6]

### 3.5 勒索软件 (**HIGH**)

lock — currently just an input lock status in the settings (pref) file, but may be used as a screenlocking

ransomware
bc — collect all contacts from the Android device and SIM card

setForward — currently not implemented, but can be used to hijack the infected device

### 3.7 蠕虫传播 (**HIGH**)

polluted DNS domains that send a notification to an unknowing victim’s device. The malicious
apps can steal personally identifiable and financial data and install additional apps. XLoader can

also hijack the infected device (i.e., send SMSs) and sports self-protection/persistence
mechanisms through device administrator privileges.

[Page 2]

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `android.intent.action.BATTERY_CHANGED` | 域名类型 |
| `android.intent.action.PACKAGE_ADDED` | 域名类型 |
| `android.intent.action.PACKAGE_REMOVED` | 域名类型 |
| `android.intent.action.PHONE_STATE` | 域名类型 |
| `android.intent.action.SCREEN_OFF` | 域名类型 |
| `android.intent.action.SCREEN_ON` | 域名类型 |
| `android.intent.action.USER_PRESENT` | 域名类型 |
| `android.media.RINGER_MODE_CHANGED` | 域名类型 |
| `android.net.conn.CONNECTIVITY_CHANGE` | 域名类型 |
| `android.net.wifi.SCAN_RESULTS` | 域名类型 |
| `android.provider.Telephony.SMS_RECEIVED` | 域名类型 |
| `android.sms.msg.action.SMS_DELIVERED` | 域名类型 |
| `android.sms.msg.action.SMS_SEND` | 域名类型 |
| `com.Loader.start` | 域名类型 |
| `dfg67.as44f.cvx87df` | 域名类型 |
| `ertt.fgh.nfg` | 域名类型 |
| `fddf.tre.hjgdsgkh` | 域名类型 |
| `fghdf.rtghj.hjkh` | 域名类型 |
| `gfdg.qwe.gsdg` | 域名类型 |
| `gfhd.rewq.cvxbdf` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, DNS 欺骗 |
| **综合风险** | **CRITICAL** | 检测到6类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): config_update
3. **银行木马** (CRITICAL): app_replace, phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
7. 其他行为见详细信息...
