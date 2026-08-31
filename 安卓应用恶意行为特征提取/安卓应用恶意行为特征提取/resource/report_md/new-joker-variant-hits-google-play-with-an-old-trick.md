# POPULAR POSTS - 分析报告

> **来源**: Check Point
> **发布日期**: 未知
> **作者**: Aviran Hazum
> **恶意软件名称**: POPULAR POSTS
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
CONTACT US DISCLOSURE POLICY CHECKPOINT.COM UNDER ATTACK?
Latest Publications CPR Podcast Channel Web 3.0 Security Intelligence Reports Resources About Us SUBSCRIBE SEARCH
POPULAR POSTS
ARTIFICIAL INTELLIGENCE CHATGPT
CHECK POINT RESEARCH PUBLICATIONS
OPWNAI : Cybercriminals Starting to Use
ChatGPT
CHECK POINT RESEARCH PUBLICATIONS
THREAT RESEARCH
NEW JOKER VARIANT HITS GOOGLE PLAY WITH AN OLD
TRICK
July 9, 2020
Research By: Aviran Hazum, Bogdan Melnykov, Israel Wernik
Hacking Fortnite Accounts
Overview:
我们使⽤ CChoeockki eP o以in允t’许s我 re们se⽹ar站ch的ers正 re常ce⼯n作tly、 di个sc性ov化er设ed计 a 内ne

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

2dba603773fee05232a9d21cbf6690c97172496f3bde2b456d687d920b160404 com.peason.lovinglovemessage
46a5fb5d44e126bc9758a57e9c80e013cac31b3b57d98eae66e898a264251f47 com.file.recovefiles
f6c37577afa37d085fb68fe365e1076363821d241fe48be1a27ae5edd2a35c4d com.LPlocker.lockapps
044514ed2aeb7c0f90e7a9daf60c1562dc21114f29276136036d878ce8f652ca com.remindme.alram
com.training.memorygame
f90acfa650db3e859a2862033ea1536e2d7a9ff5020b18b19f2b5dfd8dd323b3
Mitre ATT&CK

the malicious actor behind Joker adopted an old technique from the conventional PC threat landscape and used it in the mobile
app world to avoid detection by Google.
To realize the ability of subscribing app users to premium services without their knowledge or consent, the Joker utilized two ma
components ‒ the Notification Listener service that is part of the original application, and a dynamic dex file loaded from the C&C
server to perform the registration of the user to the services.
In an attempt to minimize Joker’s fingerprint, the actor behind it hid the dynamically loaded dex file from sight while still
ensuring it is able to load ‒ a technique which is well-known to developers of malware for Windows PCs. This new variant now

### 3.7 蠕虫传播 (**HIGH**)

sha256 Package Name 
db43287d1a5ed249c4376ff6eb4a5ae65c63ceade7100229555aebf4a13cebf7 com.imagecompress.android
d54dd3ccfc4f0ed5fa6f3449f8ddc37a5eff2a176590e627f9be92933da32926 com.contact.withme.texts
5ada05f5c6bbabb5474338084565893afa624e0115f494e1c91f48111cbe99f3 com.hmvoice.friendsms
2a12084a4195239e67e783888003a6433631359498a6b08941d695c65c05ecc4com.relax.relaxation.androidsms
96f269fa0d70fdb338f0f6cabf9748f6182b44eb1342c7dca2d4de85472bf789 com.cheery.message.sendsms
0d9a5dc012078ef41ae9112554cefbc4d88133f1e40a4c4d52decf41b54fc830 com.cheery.message.sendsms

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `2a12084a4195239e67e783888003a6433631359498a6b08941d695c65c05ecc4com.relax.relaxation.androidsms` | 域名类型 |
| `com.LPlocker.lockapps` | 域名类型 |
| `com.cheery.message.sendsms` | 域名类型 |
| `com.contact.withme.texts` | 域名类型 |
| `com.file.recovefiles` | 域名类型 |
| `com.hmvoice.friendsms` | 域名类型 |
| `com.imagecompress.android` | 域名类型 |
| `com.peason.lovinglovemessage` | 域名类型 |
| `com.remindme.alram` | 域名类型 |
| `com.training.memorygame` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `044514ed2aeb7c0f90e7a9daf60c1562dc21114f29276136036d878ce8f652ca` | 恶意文件 |
| `0d9a5dc012078ef41ae9112554cefbc4d88133f1e40a4c4d52decf41b54fc830` | 恶意文件 |
| `2dba603773fee05232a9d21cbf6690c97172496f3bde2b456d687d920b160404` | 恶意文件 |
| `46a5fb5d44e126bc9758a57e9c80e013cac31b3b57d98eae66e898a264251f47` | 恶意文件 |
| `5ada05f5c6bbabb5474338084565893afa624e0115f494e1c91f48111cbe99f3` | 恶意文件 |
| `96f269fa0d70fdb338f0f6cabf9748f6182b44eb1342c7dca2d4de85472bf789` | 恶意文件 |
| `d54dd3ccfc4f0ed5fa6f3449f8ddc37a5eff2a176590e627f9be92933da32926` | 恶意文件 |
| `db43287d1a5ed249c4376ff6eb4a5ae65c63ceade7100229555aebf4a13cebf7` | 恶意文件 |
| `f6c37577afa37d085fb68fe365e1076363821d241fe48be1a27ae5edd2a35c4d` | 恶意文件 |
| `f90acfa650db3e859a2862033ea1536e2d7a9ff5020b18b19f2b5dfd8dd323b3` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到2类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **蠕虫传播** (HIGH): 发现
