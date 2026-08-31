# July 2019 - 分析报告

> **来源**: Lookout
> **发布日期**: 2016/12/29
> **作者**: 未知
> **恶意软件名称**: July 2019
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯, 欧洲, 叙利亚
| 活动时间 | 未知
| 传播方式 | 即时通讯软件传播, 社交媒体传播, 蓝牙/U盘传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
SECURITY RESEARCH REPORT
Monokle
The Mobile Surveillance Tooling of the Special Technology Center
July 2019
[Page 2]
Contents
Executive Summary 3
Key Findings 4 Contributors 35
Contact information 35
Monokle Mobile Surveillanceware 5
Appendix A: Indicators of Compromise
Observed samples 5
36
Potential targets 6
SHA1s of Monokle APKs 36
Malicious functionality 7
Command and control infrastructure 36
Evidence of iOS components 11
Appendix B: YARA Rules 37
Special Technology Center (STC) 13
Monokle Android samples 37
Background 13
Security product suite by STC 14
Links between monokle an

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account, device_info

the 2016 U.S. presidential election. STC is a private defense contractor known for producing Unmanned Aerial Vehicles (UAVs)
and Radio Frequency (RF) equipment for supply to the Russian military, as well as other government customers. STC has been
operating in St. Petersburg since 2000 and has approximately 1500 employees.
Monokle, developed by STC, is an advanced mobile surveillanceware that compromises a user’s privacy by stealing personal
data stored on an infected device and exfiltrating this information to command and control infrastructure. While most of its
functionality is typical of a mobile surveillanceware, Monokle is unique in that it uses existing methods in novel ways in order to
be extremely effective at data exfiltration, even without root access. Among other things, Monokle makes extensive use of the

and Radio Frequency (RF) equipment for supply to the Russian military, as well as other government customers. STC has been
operating in St. Petersburg since 2000 and has approximately 1500 employees.
Monokle, developed by STC, is an advanced mobile surveillanceware that compromises a user’s privacy by stealing personal
data stored on an infected device and exfiltrating this information to command and control infrastructure. While most of its
functionality is typical of a mobile surveillanceware, Monokle is unique in that it uses existing methods in novel ways in order to
be extremely effective at data exfiltration, even without root access. Among other things, Monokle makes extensive use of the
Android accessibility services to exfiltrate data from third party applications and uses predictive-text dictionaries to get a sense of

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

[Page 25]
SECURITY RESEARCH REPORT
Setting Description
agentId An ID the agent receives on connection to the C2.
period The approximate interval, in seconds, that the client should wait to beacon out to the C2 using cellular data.
wifiPeriod The approximate interval, in seconds, that the client should wait to beacon out to the C2 on Wi-Fi.
An object which stores the C2 IP and port the client should connect to as well as a cert used for TLS

Potential targets 6
SHA1s of Monokle APKs 36
Malicious functionality 7
Command and control infrastructure 36
Evidence of iOS components 11
Appendix B: YARA Rules 37
Special Technology Center (STC) 13

Potential targets 6
SHA1s of Monokle APKs 36
Malicious functionality 7
Command and control infrastructure 36
Evidence of iOS components 11
Appendix B: YARA Rules 37
Special Technology Center (STC) 13

SECURITY RESEARCH REPORT
Setting Description
agentId An ID the agent receives on connection to the C2.
period The approximate interval, in seconds, that the client should wait to beacon out to the C2 using cellular data.
wifiPeriod The approximate interval, in seconds, that the client should wait to beacon out to the C2 on Wi-Fi.
An object which stores the C2 IP and port the client should connect to as well as a cert used for TLS
socketAddr

### 3.4 C2 反检测 (**HIGH**)

Attacker-controlled mobile devices 22
Unique control phrases 23
Detailed Malware Analysis 23
Second stage encrypted DEX files 23
Configuration files 23
Inclusion of Xposed modules 27
Communication and serialization protocols 27

### 3.7 蠕虫传播 (**HIGH**)

• Download attacker-specified files.
• Get nearby cell tower info. • Collect account information
• Reboot a device. and retrieve messages for
• List installed applications. WhatsApp, Instagram, VK,
• Interact with popular office applications Skype, imo.
• Retrieve accounts and
to retrieve document text.

The malware is notable for its extensive use of
accessibility services to capture data from third
party apps such as Microsoft Word, Google Docs,
Facebook messenger, Whatsapp, imo, Viber,
Skype, WeChat, VK, Line, and Snapchat.
Evidence of iOS components
In several Android samples of Monokle, there are unused commands and data transfer objects (DTOs) defined which point to the

• Retrieve calendar information including
via keywords (control phrases) • Make outgoing calls.
name of event, when and where it is
delivered via SMS or from
taking place, and description.
designated control phones. • Record calls.
2 https://en.wikipedia.org/wiki/Ahrar_al-Sham

### 3.8 权限滥用 (**HIGH**)

data stored on an infected device and exfiltrating this information to command and control infrastructure. While most of its
functionality is typical of a mobile surveillanceware, Monokle is unique in that it uses existing methods in novel ways in order to
be extremely effective at data exfiltration, even without root access. Among other things, Monokle makes extensive use of the
Android accessibility services to exfiltrate data from third party applications and uses predictive-text dictionaries to get a sense of
the topics of interest to a target. Monokle will also attempt to record the screen during a screen unlock event so as to compromise
a user’s PIN, pattern or password.
Monokle appears in a very limited set of applications which implies attacks using Monokle are highly targeted. Many of these

Monokle, developed by STC, is an advanced mobile surveillanceware that compromises a user’s privacy by stealing personal
data stored on an infected device and exfiltrating this information to command and control infrastructure. While most of its
functionality is typical of a mobile surveillanceware, Monokle is unique in that it uses existing methods in novel ways in order to
be extremely effective at data exfiltration, even without root access. Among other things, Monokle makes extensive use of the
Android accessibility services to exfiltrate data from third party applications and uses predictive-text dictionaries to get a sense of
the topics of interest to a target. Monokle will also attempt to record the screen during a screen unlock event so as to compromise
a user’s PIN, pattern or password.

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `109.167.231` | 域名类型 |
| `109.167.231.10` | 域名类型 |
| `136.243.219` | 域名类型 |
| `136.243.219.233` | 域名类型 |
| `149.154.65` | 域名类型 |
| `149.154.65.55` | 域名类型 |
| `178.63.140` | 域名类型 |
| `178.63.140.53` | 域名类型 |
| `185.117.89` | 域名类型 |
| `185.117.89.238` | 域名类型 |
| `185.23.17` | 域名类型 |
| `185.23.17.13` | 域名类型 |
| `185.248.162` | 域名类型 |
| `185.248.162.64` | 域名类型 |
| `185.48.56` | 域名类型 |
| `185.48.56.81` | 域名类型 |
| `188.165.165` | 域名类型 |
| `188.165.165.246` | 域名类型 |
| `188.165.29` | 域名类型 |
| `188.165.29.60` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `109.167.231.10` | 服务器 |
| `136.243.219.233` | 服务器 |
| `149.154.65.55` | 服务器 |
| `178.63.140.53` | 服务器 |
| `185.117.89.238` | 服务器 |
| `185.23.17.13` | 服务器 |
| `185.23.17.2` | 服务器 |
| `185.248.162.64` | 服务器 |
| `185.48.56.81` | 服务器 |
| `188.165.165.246` | 服务器 |
| `188.165.29.60` | 服务器 |
| `192.168.49.24` | 服务器 |
| `212.116.121.232` | 服务器 |
| `217.172.20.24` | 服务器 |
| `37.252.121.133` | 服务器 |
| `46.4.180.48` | 服务器 |
| `77.37.200.61` | 服务器 |
| `88.99.111.46` | 服务器 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `https://appsgeyser.io/3023577/UzbekChat` | 钓鱼/下载 |
| `https://en.wikipedia.org/wiki/Ahrar_al-Sham` | 钓鱼/下载 |
| `https://en.wikipedia.org/wiki/Caucasus#Endonyms_and_exonyms` | 钓鱼/下载 |
| `https://en.wikipedia.org/wiki/Ingushetia` | 钓鱼/下载 |
| `https://github.com/rtyley/spongycastle` | 钓鱼/下载 |
| `https://people.apache.org/~thejas/thrift-0.9/javadoc/org/apache/thrift/protocol/TCompactProtocol.html#writeI32(int` | 钓鱼/下载 |
| `https://people.apache.org/~thejas/thrift-0.9/javadoc/org/apache/thrift/protocol/TCompactProtocol.html#writeString(java.l` | 钓鱼/下载 |
| `https://www.airforce-technology.com/projects/orlan-10-unmanned-aerial-vehicle-uav` | 钓鱼/下载 |
| `https://www.linkedin.com/company/stc-ltd./about` | 钓鱼/下载 |
| `https://www.stc-spb.ru` | 钓鱼/下载 |
| `https://www.xda-developers.com/xposed-framework-hub` | 钓鱼/下载 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @lookout | C2/通信 |
| @mail | C2/通信 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 即时通讯软件传播, 社交媒体传播, 蓝牙/U盘传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
5. **权限滥用** (HIGH): 发现
