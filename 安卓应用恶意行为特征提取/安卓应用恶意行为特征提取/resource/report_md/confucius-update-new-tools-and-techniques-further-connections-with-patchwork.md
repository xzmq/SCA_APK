# APT & Targeted Attacks - 分析报告

> **来源**: Trend Micro
> **发布日期**: May 23, 2018
> **作者**: Daniel Lunghi
> **恶意软件名称**: APT & Targeted Attacks
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
APT & Targeted Attacks
Confucius Update: New Techniques, More Patchwork Links
We look into the latest tools and techniques used by Confucius, as the threat actor seems to have a new modus operandi, setting up two new websites and new payloads with which to
compromise its targets.
By: Daniel Lunghi, Jaromir Horejsi
May 23, 2018
Read time: 7 min (1974 words)
Updated the appendix on August 30, 2018 to fix formatting and add new information.
Back in February, we noted the similarities between the Patchwork and Confucius groups and
found that, in addition to the similarities in their malwa

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account

thousands of women app.”

The app’s features are similar to the previous malicious Android application, such as having the
ability to record audio and steal SMS, accounts, contacts and certain file types from specific
directories. In addition, the application now retrieves the last known location and uses the
development platform Google Firebase to upload the stolen content.

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

[Page 13]
The other file stealer
(1f0dabd61947b6df8a392b77a0eae33777be3caad13698aecc223b54ab4b859a, Detected as
TROJ_DELF.XXWZ) is related to a domain reported in September 2016. That report also
mentioned InPage software targeting and Delphi backdoors.
Figure 10. Left: Confucius group, Middle: Hangover group, Right: Unnamed group

Figure 4. Sample of the app’s code

[Page 6]
Periodically, the malware tries to contact the Command-and-Control (C&C) server with the
username encoded into parameters. Based on the information they retrieve, the operators can
then decide to instruct the malware to download the second stage payload. This function is
similar to the various versions of backdoors (such as sctrls and sip_telephone) that we analyzed

Figure 4. Sample of the app’s code

[Page 6]
Periodically, the malware tries to contact the Command-and-Control (C&C) server with the
username encoded into parameters. Based on the information they retrieve, the operators can
then decide to instruct the malware to download the second stage payload. This function is
similar to the various versions of backdoors (such as sctrls and sip_telephone) that we analyzed

Figure 4. Sample of the app’s code

[Page 6]
Periodically, the malware tries to contact the Command-and-Control (C&C) server with the
username encoded into parameters. Based on the information they retrieve, the operators can
then decide to instruct the malware to download the second stage payload. This function is
similar to the various versions of backdoors (such as sctrls and sip_telephone) that we analyzed

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

[Page 5]
sends some basic information (username, antivirus, IP address, and operating system version)
encrypted using triple Data Encryption Standard (DES).

Figure 4. Sample of the app’s code

### 3.5 勒索软件 (**HIGH**)

[Page 17]
Patchwork uses email as an entry point, which is why securing the email gateway is
important. Trend Micro™ Email Security is a no-maintenance cloud solution that delivers
continuously updated protection to stop spam, malware, spear phishing, ransomware, and
advanced targeted attacks before they reach the network. Trend Micro™ Email
Inspector and InterScan™ Web Security prevent malware from ever reaching end users. At the
endpoint level, Trend Micro™ Smart Protection Suites deliver several capabilities that minimize

### 3.7 蠕虫传播 (**HIGH**)

.pptx Microsoft Powerpoint presentation
.png, .jpg, .jpeg Image file
.pst, .ost Microsoft Outlook file 
.csv Spreadsheet file
It then sends them via a POST HTTP request to windefendr[.]com/description.php.

[Page 8]

thousands of women app.”

The app’s features are similar to the previous malicious Android application, such as having the
ability to record audio and steal SMS, accounts, contacts and certain file types from specific
directories. In addition, the application now retrieves the last known location and uses the
development platform Google Firebase to upload the stolen content.

### 3.8 权限滥用 (**HIGH**)

equipped to handle the more advanced threats that groups like Confucius use in their attacks.
Since these teams also handle the day-to-day IT requirements of the organization, taking on a
more involved and proactive stance may not be easy. In this case, an organization can look into
third party security providers who can handle specialized work, such as root cause analysis and

detailed research, and also provide a remediation plan that gives organizations a better chance
against advanced threats.

---

## 4. IoCs (威胁指标)

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `1f0dabd61947b6df8a392b77a0eae33777be3caad13698aecc223b54ab4b859a` | 恶意文件 |
| `472ea4929c5e0fb4e29597311ed90a14c57bc67fbf26f81a3aac042aa3dccb55` | 恶意文件 |
| `795ae4097aa3bd5932be4110f6bd992f46d605d4c9e3afced314454d35395a59` | 恶意文件 |
| `cca74bb322ad7833a21209b1418c9837e30983daec30d199a839f46075ee72f2` | 恶意文件 |
| `d971842441c83c1bba05742d124620f5741bb5d5da9ffb31f06efa4bbdcf04ee` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到6类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): twitter
4. **勒索软件** (HIGH): 发现
5. **蠕虫传播** (HIGH): 发现
7. 其他行为见详细信息...
