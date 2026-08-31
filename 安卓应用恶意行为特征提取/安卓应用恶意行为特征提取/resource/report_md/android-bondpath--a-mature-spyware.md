# raise an alert. - 分析报告

> **来源**: 未知
> **发布日期**: since 2016
> **作者**: 未知
> **恶意软件名称**: raise an alert.
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
FFOORRTTIIGGUUAARRDD LLAABBSS TTHHRREEAATT RREESSEEAARRCCHH
AAnnddrrooiidd//BBoonnddPPaatthh:: aa MMaattuurree SSppyywwaarree
By Axelle Apvrille| August 23, 2018
W
e have recently stumbled on several active samples of an Android spyware. They belong to a family we have named BondPath (also known
as PathCall or Dingwe), which was first reported in May 2016. While our customers have been protected against that malware since 2016, in
July 2018 we discovered that some samples are still in the wild and continue to be a threat to unprotected smartphones.
This malware poses as a Google Play 

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

[Page 4]
Decompiled code of Android/BondPath posting battery status report
The infected smartphone can also be controlled remotely to retrieve even more data. In particular, it will retrieve chats from WhatsApp, Skype,
Viber, Line, Facebook, and BBM. To accomplish this, the spy sends the remote command PULLREQUEST_xxxx to the malware. For example,
PULLREQUEST_skypelog or PULLREQUEST_fbmessenger etc.
Spying on the Spy: Remote Panel

[Page 8]
IOCs:
0918c205c6867e24080f8950ce82f48c56822187429c35cde3f37f36554bff57
2ff501b0a0607000262de40e6a84da8adc3b91a4f943b97976ec5dd09376d223
5e0cbe1e6ab99cbb274e18b00d49c4b160fedd2e25c79a45531908a92a3cf790
-- the Crypto Girl

[Page 4]
Decompiled code of Android/BondPath posting battery status report
The infected smartphone can also be controlled remotely to retrieve even more data. In particular, it will retrieve chats from WhatsApp, Skype,
Viber, Line, Facebook, and BBM. To accomplish this, the spy sends the remote command PULLREQUEST_xxxx to the malware. For example,
PULLREQUEST_skypelog or PULLREQUEST_fbmessenger etc.
Spying on the Spy: Remote Panel

[Page 4]
Decompiled code of Android/BondPath posting battery status report
The infected smartphone can also be controlled remotely to retrieve even more data. In particular, it will retrieve chats from WhatsApp, Skype,
Viber, Line, Facebook, and BBM. To accomplish this, the spy sends the remote command PULLREQUEST_xxxx to the malware. For example,
PULLREQUEST_skypelog or PULLREQUEST_fbmessenger etc.
Spying on the Spy: Remote Panel

### 3.4 C2 反检测 (**HIGH**)

SMS: incoming and outgoing
Collected information is sent to a remote server via HTTP. These packets contain:
Type: (e.g reguser, deviceinfo, appconfig)
Data: this is the payload of the packet. It is encrypted with AES-ECB using PKCS5 Padding and a hard coded key. It is then encoded with
Base64 and then URL-encoded.
Hash: an MD5 hash of the payload
These procedures indicate that the malware author(s) have a weak knowledge of cryptography (poor choice of block chaining, padding, no

### 3.5 勒索软件 (**HIGH**)

Threat Research
FortiGuard Labs
Threat Map
Ransomware Prevention
Connect With Us
Fortinet Community
Partner Portal

### 3.7 蠕虫传播 (**HIGH**)

[Page 4]
Decompiled code of Android/BondPath posting battery status report
The infected smartphone can also be controlled remotely to retrieve even more data. In particular, it will retrieve chats from WhatsApp, Skype,
Viber, Line, Facebook, and BBM. To accomplish this, the spy sends the remote command PULLREQUEST_xxxx to the malware. For example,
PULLREQUEST_skypelog or PULLREQUEST_fbmessenger etc.
Spying on the Spy: Remote Panel

Decompiled code of Android/BondPath posting battery status report
The infected smartphone can also be controlled remotely to retrieve even more data. In particular, it will retrieve chats from WhatsApp, Skype,
Viber, Line, Facebook, and BBM. To accomplish this, the spy sends the remote command PULLREQUEST_xxxx to the malware. For example,
PULLREQUEST_skypelog or PULLREQUEST_fbmessenger etc.
Spying on the Spy: Remote Panel

[Page 5]

Emails
Files on the phone
Installed applications
SMS: incoming and outgoing
Collected information is sent to a remote server via HTTP. These packets contain:
Type: (e.g reguser, deviceinfo, appconfig)
Data: this is the payload of the packet. It is encrypted with AES-ECB using PKCS5 Padding and a hard coded key. It is then encoded with

---

## 4. IoCs (威胁指标)

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `0918c205c6867e24080f8950ce82f48c56822187429c35cde3f37f36554bff57` | 恶意文件 |
| `2ff501b0a0607000262de40e6a84da8adc3b91a4f943b97976ec5dd09376d223` | 恶意文件 |
| `5e0cbe1e6ab99cbb274e18b00d49c4b160fedd2e25c79a45531908a92a3cf790` | 恶意文件 |

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

1. **远程控制** (CRITICAL): config_update
2. **C2 反检测** (HIGH): 发现
3. **勒索软件** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
