# APT & Targeted Attacks - 分析报告

> **来源**: Trend Micro
> **发布日期**: Aug 29, 2018
> **作者**: Daniel Lunghi
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
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
APT & Targeted Attacks
Bahamut, Confucius and Patchwork Connected to Urpage
We dig deeper into the possible connection between cyberattacks by focusing on the similarities an unnamed threat actor shares with Confucius, Patchwork, and Bahamut. For the sake
of this report, we will call this unnamed threat actor “Urpage.”
By: Daniel Lunghi, Ecular Xu
Aug 29, 2018
Read time: 6 min (1672 words)
In the process of monitoring changes in the threat landscape, we get a clearer insight into the
way threat actors work behind the schemes. In this case we dig deeper into the possible
connection bet

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts

[Page 4]
Android targeting
As with Bahamut applications, once downloaded and executed, it showed multiple malicious
features that deal with stealing information. Some of these features are listed below.
Retrieves basic information like network information and MAC address from an infected phone

SMS stealing

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

The Bahamut Link
Fake websites
The link between Bahamut and Urpage can be best discussed by way of the multiple malicious
Android samples that matched Bahamut's code and had C&C belonging to the Urpage
infrastructure. Some of these C&C websites also act as phishing sites that lure users into
downloading these very applications. The threat actor sets up these fake websites describing the
application and linking to the Google Play Store to download it, like in the case of the malicious

### 3.4 C2 反检测 (**HIGH**)

Pictures .jpeg, .jpg

Of note is one specific application that had a different purpose from the others. This application
has the same encryption routine as other Urpage applications. Instead of stealing documents or

[Page 5]
images, it works on top of a modified version of the legitimate Threema, an end-to-end

### 3.7 蠕虫传播 (**HIGH**)

File type File extensions
Document files .txt, .csv, .doc, .docx, .xls, .xlsx, .pdf
WhatsApp databases .db.crypt5 to .db.crypt12
Geolocation related files .kml, .kmz, .gmx, .aqm
Audio files .mp3, .opus
Videos .mp4, .amr, .wmv, .3gp,

features that deal with stealing information. Some of these features are listed below.
Retrieves basic information like network information and MAC address from an infected phone

SMS stealing

Contacts stealing

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `ch.threema.app` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `434d34c0502910c562f5c6840694737a2c82a8c44004fa58c7c457b08aac17bd` | 恶意文件 |
| `f1a54dca2fdfe59ec3f537148460364fb5d046c9b4e7db5fc819a9732ae0e063` | 恶意文件 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
