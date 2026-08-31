# Banking Trojans continue to surface - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: keep testing the vigilance of Android us
> **恶意软件名称**: Banking Trojans continue to surface
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Malware
Banking Trojans continue to surface
on Google Play
The malicious apps have all been removed from the official Android store but not before the
apps were installed by almost 30,000 users
Lukas Stefanko
24 Oct 2018 • 5 min. read
[Page 2]
[Page 3]
Malware authors keep testing the vigilance of Android users by sneaking disguised mobile banking
Trojans into the Google Play store. We’ve recently analyzed a set of 29 such stealthy Trojans, found
in the official Android store from August until early October 2018, masquerading as device boosters
and cleaners, battery managers and even 

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account

[Page 3]
Malware authors keep testing the vigilance of Android users by sneaking disguised mobile banking
Trojans into the Google Play store. We’ve recently analyzed a set of 29 such stealthy Trojans, found
in the official Android store from August until early October 2018, masquerading as device boosters
and cleaners, battery managers and even horoscope-themed apps.
Unlike the increasingly prevalent malicious apps relying purely on impersonating legitimate

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: webview

Indicators of Compromise (IoCs)
App name Package name Hash Instal
Power
com.puredevlab.powermanager 7C13ADEFC2CABD85AD8F486C3CBDB6379811A097 10+
Manager
Astro Plus com.astro.plus 24D2ED751A33BD965A01FA87D7A187D14D0B0849 0+
Master

victim’s device with tailor-made phishing forms. Aside from this, they can intercept and redirect
text messages to bypass SMS-based two-factor-authentication, intercept call logs, and download
and install other apps on the compromised device. These malicious apps were uploaded under
mostly different developer names and guises, but code similarities and a shared C&C server suggest
the apps are the work of a single attacker or group.

[Page 4]

Unlike the increasingly prevalent malicious apps relying purely on impersonating legitimate
financial institutions and displaying bogus login screens, these apps belong to the category of
sophisticated mobile banking malware with complex functionality and a heavy focus on stealth.
These remotely controlled Trojans are capable of dynamically targeting any apps found on the
victim’s device with tailor-made phishing forms. Aside from this, they can intercept and redirect
text messages to bypass SMS-based two-factor-authentication, intercept call logs, and download
and install other apps on the compromised device. These malicious apps were uploaded under

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

[Page 1]
Malware
Banking Trojans continue to surface
on Google Play
The malicious apps have all been removed from the official Android store but not before the
apps were installed by almost 30,000 users

[Page 1]
Malware
Banking Trojans continue to surface
on Google Play
The malicious apps have all been removed from the official Android store but not before the
apps were installed by almost 30,000 users

### 3.4 C2 反检测 (**HIGH**)

[Page 5]
Figure 2 – A fake error message displayed by one of these Trojans upon launch
Regardless of which of the preceding activities one of these apps displays, the main malicious
functionality is hidden in an encrypted payload located in each app’s assets. This payload is encoded
using base64 and then encrypted with an RC4 cipher using a hardcoded key. The first stage of the
malware’s activity is a dropper that initially checks for the presence of an emulator or a sandbox. If
these checks fail, it then decrypts and drops a loader, and a payload that contains the actual

### 3.7 蠕虫传播 (**HIGH**)

sophisticated mobile banking malware with complex functionality and a heavy focus on stealth.
These remotely controlled Trojans are capable of dynamically targeting any apps found on the
victim’s device with tailor-made phishing forms. Aside from this, they can intercept and redirect
text messages to bypass SMS-based two-factor-authentication, intercept call logs, and download
and install other apps on the compromised device. These malicious apps were uploaded under
mostly different developer names and guises, but code similarities and a shared C&C server suggest
the apps are the work of a single attacker or group.

### 3.8 权限滥用 (**HIGH**)

device, intercept and send SMS messages, and download and install additional applications of the
operator’s choice. The most significant feature is that the malware can dynamically impersonate
any app installed on a compromised device. This is achieved by obtaining the HTML code of the
apps installed on the device and using that code to overlay legitimate apps with bogus forms once
the legitimate apps are launched, giving the victim very little chance to notice something is amiss.
How to stay safe
Fortunately, these particular banking Trojans (the full list can be found in the IoCs section) do not

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `bl.masterbooster.pro` | 域名类型 |
| `bnb.massclean.boost` | 域名类型 |
| `bnm.massclean.boost` | 域名类型 |
| `boost.your.phone` | 域名类型 |
| `com.astro.plus` | 域名类型 |
| `com.dailyhoroscope.free` | 域名类型 |
| `com.dayhoroscope.en` | 域名类型 |
| `com.horo2018i.up` | 域名类型 |
| `com.horochart.uk` | 域名类型 |
| `com.puredevlab.powermanager` | 域名类型 |
| `cpu.cleanpti.clo` | 域名类型 |
| `day.horocom.ww` | 域名类型 |
| `fr.dayy.horos` | 域名类型 |
| `fx.acleaner.e2018` | 域名类型 |
| `ghl.phoneboost.com` | 域名类型 |
| `gmd.horobest.ty` | 域名类型 |
| `horo.glue.zodnow` | 域名类型 |
| `mc.boostpower.cf` | 域名类型 |
| `mc.boostpower.lf` | 域名类型 |
| `my.horoscop.br` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到6类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): webview
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): 发现
5. **蠕虫传播** (HIGH): 发现
7. 其他行为见详细信息...
