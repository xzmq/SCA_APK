# MALWARE DESCRIPTIONS 07 APR 2020 3 minute read - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: IGOR GOLOVIN
> **恶意软件名称**: MALWARE DESCRIPTIONS 07 APR 2020 3 minute read
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Unkillable xHelper and a Trojan matryoshka
MALWARE DESCRIPTIONS 07 APR 2020 3 minute read
// AUTHORS
IGOR GOLOVIN
It was the middle of last year that we detected the start of mass attacks by the xHelper Trojan on
Android smartphones, but even now the malware remains as active as ever. The main feature of
xHelper is entrenchment — once it gets into the phone, it somehow remains there even after the
user deletes it and restores the factory settings. We conducted a thorough study to determine
how xHelper’s creators furnished it with such survivability.
[Page 2]
Share of Kaspersky users a

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: device_info

172. 104. 209. 55 IN THE SAME CATEGORY
172. 104. 219. 210
172. 104. 218. 146
Lumma Stealer – Tracking
45. 79. 177. 230 distribution channels
45. 33. 0. 123
45. 79. 77. 161

### 3.2 远程控制 (**CRITICAL**)

How to get rid of xHelper?
Let’s analyze the family’s logic based on the currently active sample Trojan-
Dropper.AndroidOS.Helper.h. The malware disguises itself as a popular cleaner and speed-up app
C&C
for smartphones, but in reality there is nothing useful about it: after installation, the “cleaner” simply
MD5
disappears and is nowhere to be seen either on the main screen or in the program menu. You can

at system startup. All files in the target folders are assigned the immutable attribute, which makes
it difficult to delete the malware, because the system does not allow even superusers to delete
files with this attribute. However, this self-defense mechanism employed by the Trojan can be
countered by deleting this attribute using the chattr command.
The question arises: if the malware is able to remount the system partition in write mode in order to
copy itself there, can the user adopt the same strategy to delete it? Triada’s creators also
contemplated this question, and duly applied another protection technique that involved modifying

mount file systems) in libc, thereby preventing the user from mounting the /system partition in
write mode.
On top of that, the Trojan downloads and installs several more malicious programs (for
example, HEUR:Trojan-Dropper.AndroidOS.Necro.z), and deletes root access control applications,
such as Superuser.
How to get rid of xHelper?
As follows from the above, simply removing xHelper does not entirely disinfect the system. The

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: app_replace, phishing

45. 33. 0. 123
45. 79. 77. 161
45. 33. 120. 75
Download a banker to track
45. 79. 171. 160 your parcel
172. 104. 210. 193
45. 33. 0. 176

### 3.4 C2 反检测 (**HIGH**)

MD5
disappears and is nowhere to be seen either on the main screen or in the program menu. You can
see it only by inspecting the list of installed apps in the system settings.
The Trojan’s payload is encrypted in the file /assets/firehelper.jar (since its encryption is practically
unchanged from earlier versions, it was not difficult to decrypt). Its main task is to send information
about the victim’s phone (android_id, manufacturer, model, firmware version, etc.) to
https://lp.cooktracking[.]com/v1/ls/get…

### 3.5 勒索软件 (**HIGH**)

45. 79. 151. 241
172. 104. 213. 65
172. 104. 211. 117 Ymir: new stealthy
ddl. okgoodmobi[. ]com ransomware in the wild
MD5 QSC: A multi-plugin
framework used by
CloudComputating group in

### 3.6 广告欺诈 (**MEDIUM**)

malware at the first opportunity.
FROM THE SAME AUTHORS
Pig in a poke: smartphone
adware
Aggressive in-app advertising
in Android
Smartphone shopaholic

### 3.8 权限滥用 (**HIGH**)

Dropper.AndroidOS.Helper.b, is decrypted and launched. This in turn runs the malware Trojan-
Downloader.AndroidOS.Leech.p, which further infects the device.
Leech.p is tasked with downloading our old friend HEUR:Trojan.AndroidOS.Triada.dd with a set of
exploits for obtaining root privileges on the victim’s device.
GREAT WEBINARS
13 MAY 2021, 1:00PM
GReAT Ideas. Balalaika Edition

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `172.104.215.170` | 域名类型 |
| `45.79.110.191` | 域名类型 |
| `com.diag.patches.vm8u` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `172.104.215.170` | 服务器 |
| `23.239.4.169` | 服务器 |
| `45.33.9.178` | 服务器 |
| `45.79.110.191` | 服务器 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): device_info
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): app_replace, phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
8. 其他行为见详细信息...
