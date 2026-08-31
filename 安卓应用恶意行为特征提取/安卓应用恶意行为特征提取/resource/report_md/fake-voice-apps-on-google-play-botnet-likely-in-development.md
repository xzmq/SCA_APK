# have included evasive techniques and multi-stage infection behavior. - 分析报告

> **来源**: Trend Micro
> **发布日期**: Nov 27, 2018
> **作者**: Echo Duan
Nov
> **恶意软件名称**: have included evasive techniques and multi-stage infection behavior.
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
Malware
Fake Voice Apps on Google Play, Botnet Development
Several apps on Google Play posing as legitimate voice messenger platforms have automated functions such as fake survey pop-ups and fraudulent ad clicks. Variants were observed to
have included evasive techniques and multi-stage infection behavior.
By: Echo Duan
Nov 27, 2018
Read time: 3 min (678 words)
We noticed several uploaded apps on Google Play posing as legitimate voice messenger
platforms, with suspicious automated functions such as automatic pop-ups of fake surveys and
fraudulent ad clicks. Observed variants of these 

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

exploits, privacy leaks, and application vulnerability. Indicators of Compromise
App URL SHA256
com.bitv.freeaudiomessages
3f7b367488e761f89b4adeb5dc1b961766c238d41ebb9fbd726da8499d1fce26
7a4813f68936a37fce366154a608ad307084336abc205b55f80b0a6788d067ac
com.wififree.messenger
811f12ea658f9325eede5afcc9898aaf37d1e0eafab84e94b9d3b13adcc6131f

to be subtle by using lightweight modular downloaders to compromise unknowing users’
gadgets. While the published uploaders of these apps are different, we suspect that the apps
came from the same authors since the codes are similar to each other. Once downloaded, the
first component connects with the C&C server, then decrypts and executes the payload.

[Page 4]
Figure 3. Order of payload execution.

https://play.google.com/store/apps/details?id=com.netaudio.vam
https://play.google.com/store/apps/details?id=com.voicedata.justvoicemessenger
hxxp://vilayierie.live:443
Command and Control hxxp://aspiet.club:443
hxxp://213.239.222.7:8081

[Page 12]

https://play.google.com/store/apps/details?id=com.netaudio.vam
https://play.google.com/store/apps/details?id=com.voicedata.justvoicemessenger
hxxp://vilayierie.live:443
Command and Control hxxp://aspiet.club:443
hxxp://213.239.222.7:8081

[Page 12]

### 3.6 广告欺诈 (**MEDIUM**)

[Page 1]
Malware
Fake Voice Apps on Google Play, Botnet Development
Several apps on Google Play posing as legitimate voice messenger platforms have automated functions such as fake survey pop-ups and fraudulent ad clicks. Variants were observed to
have included evasive techniques and multi-stage infection behavior.
By: Echo Duan
Nov 27, 2018

### 3.7 蠕虫传播 (**HIGH**)

[Page 1]
Malware
Fake Voice Apps on Google Play, Botnet Development
Several apps on Google Play posing as legitimate voice messenger platforms have automated functions such as fake survey pop-ups and fraudulent ad clicks. Variants were observed to
have included evasive techniques and multi-stage infection behavior.
By: Echo Duan
Nov 27, 2018

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `213.239.222` | 域名类型 |
| `com.bestvoice.messenger` | 域名类型 |
| `com.bitv.freeaudiomessages` | 域名类型 |
| `com.netaudio.vam` | 域名类型 |
| `com.onlinevoice.playerapp` | 域名类型 |
| `com.voicedata.justvoicemessenger` | 域名类型 |
| `com.wififree.messenger` | 域名类型 |
| `play.google.com` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `213.239.222.7` | 服务器 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `3f7b367488e761f89b4adeb5dc1b961766c238d41ebb9fbd726da8499d1fce26` | 恶意文件 |
| `7a4813f68936a37fce366154a608ad307084336abc205b55f80b0a6788d067ac` | 恶意文件 |
| `811f12ea658f9325eede5afcc9898aaf37d1e0eafab84e94b9d3b13adcc6131f` | 恶意文件 |
| `92ea01d0198506d5a43e3cfccf7b2661c131c57e8d260fbf34760f01a897b0cb` | 恶意文件 |
| `9742148afe109e8ab25ec81f58aee8befed6be20affa7b2a71702a65d4bc377c` | 恶意文件 |
| `cabe057cf19ddd54a1489e0db74d0c8833cea501c4b4a22b7953a6e7d1fd9391` | 恶意文件 |
| `dddb84da1b4f8914f31781a1a8a46c028dbb776a891d198b5d4b78c3c9a62c8d` | 恶意文件 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `https://play.google.com/store/apps/details?id=com.bestvoice.messenger` | 钓鱼/下载 |
| `https://play.google.com/store/apps/details?id=com.bitv.freeaudiomessages` | 钓鱼/下载 |
| `https://play.google.com/store/apps/details?id=com.netaudio.vam` | 钓鱼/下载 |
| `https://play.google.com/store/apps/details?id=com.onlinevoice.playerapp` | 钓鱼/下载 |
| `https://play.google.com/store/apps/details?id=com.voicedata.justvoicemessenger` | 钓鱼/下载 |
| `https://play.google.com/store/apps/details?id=com.wififree.messenger` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到3类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **广告欺诈** (MEDIUM): 发现
3. **蠕虫传播** (HIGH): 发现
