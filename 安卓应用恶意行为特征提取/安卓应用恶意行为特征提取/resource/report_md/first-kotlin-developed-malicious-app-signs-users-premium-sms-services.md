# disgused as Swift Cleaner, a tool that optimizes Android devices. - 分析报告

> **来源**: Trend Micro
> **发布日期**: Jan 09, 2018
> **作者**: Lorin Wu
Jan
> **恶意软件名称**: disgused as Swift Cleaner, a tool that optimizes Android devices.
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
Mobile
First Kotlin-Developed Malicious App Spotted
We spotted a malicious app that appears to be the first developed using Kotlin—an open-source programming language for multiplatform applications. Samples from Google Play were
disgused as Swift Cleaner, a tool that optimizes Android devices.
By: Lorin Wu
Jan 09, 2018
Read time: 3 min (756 words)
We spotted a malicious app (detected by Trend Micro as ANDROIDOS_BKOTKLIND.HRX) that
appears to be the first developed using Kotlin—an open-source programming language for
modern multiplatform applications. The samples we found on Google Pla

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

appears to be the first developed using Kotlin—an open-source programming language for
modern multiplatform applications. The samples we found on Google Play posed as Swift
Cleaner, a utility tool that cleans and optimizes Android devices. The malicious app, which has
1,000-5,000 installs as of writing, is capable of remote command execution, information theft,
SMS sending, URL forwarding, and click ad fraud. It can also sign up users for premium SMS
subscription services without their permission.

5886316C0B54BBB7CE6978ACDB1AB4E2CF2B1494647B9D9AD014802E6BF5C7B8 com[.]pho[.]nec[.]pcs
Cleaner
Swift
AEEF3FF7CC543BBACB6AB4DF8DA639B98BE8F3C225678A4D0935F467BC6D720E com[.]pho[.]nec[.]pcs
Cleaner

[Page 11]

Technical analysis
Upon launching Swift Cleaner, the malware sends the victim’s device information to its remote
server and starts the background service to get tasks from its remote C&C server. When the

[Page 5]
device gets infected the first time, the malware will send an SMS to a specified number provided

appears to be the first developed using Kotlin—an open-source programming language for
modern multiplatform applications. The samples we found on Google Play posed as Swift
Cleaner, a utility tool that cleans and optimizes Android devices. The malicious app, which has
1,000-5,000 installs as of writing, is capable of remote command execution, information theft,
SMS sending, URL forwarding, and click ad fraud. It can also sign up users for premium SMS
subscription services without their permission.

### 3.6 广告欺诈 (**MEDIUM**)

modern multiplatform applications. The samples we found on Google Play posed as Swift
Cleaner, a utility tool that cleans and optimizes Android devices. The malicious app, which has
1,000-5,000 installs as of writing, is capable of remote command execution, information theft,
SMS sending, URL forwarding, and click ad fraud. It can also sign up users for premium SMS
subscription services without their permission.

[Page 2]

modern multiplatform applications. The samples we found on Google Play posed as Swift
Cleaner, a utility tool that cleans and optimizes Android devices. The malicious app, which has
1,000-5,000 installs as of writing, is capable of remote command execution, information theft,
SMS sending, URL forwarding, and click ad fraud. It can also sign up users for premium SMS
subscription services without their permission.

[Page 2]

### 3.7 蠕虫传播 (**HIGH**)

modern multiplatform applications. The samples we found on Google Play posed as Swift
Cleaner, a utility tool that cleans and optimizes Android devices. The malicious app, which has
1,000-5,000 installs as of writing, is capable of remote command execution, information theft,
SMS sending, URL forwarding, and click ad fraud. It can also sign up users for premium SMS
subscription services without their permission.

[Page 2]

---

## 4. IoCs (威胁指标)

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `2856F3D1282DDC6BCFE65B0C91A87D998EDCCB777387E3F998BC3B6F1D0B3342` | 恶意文件 |
| `329B9C5670ECDF25248E484E23C21BBC86F943D7573FF131C0DC71BC80812D1C` | 恶意文件 |
| `4F649E0EA6A6F022E7A5701CECB5B7653D1334EB40918E52DB8F3DAACFB3B660` | 恶意文件 |
| `5886316C0B54BBB7CE6978ACDB1AB4E2CF2B1494647B9D9AD014802E6BF5C7B8` | 恶意文件 |
| `621092856E20E628A577DBE9248649EAE78D1AF611D9168635B22057C6C7552B` | 恶意文件 |
| `77D0C7DD4B3D87BE6D9DFB0A9C371B4D8EEADCCB8FDE41D942F1C35E5E3EC063` | 恶意文件 |
| `7D3E61C2C58906E09D56121BE94601744E362E6F8C6B7BF87472B62B0CF8CE57` | 恶意文件 |
| `AB2C4886A4E0681A55B29C653B506B66721A3F36A1B098AFA7F56DA6F89BF5DE` | 恶意文件 |
| `AEEF3FF7CC543BBACB6AB4DF8DA639B98BE8F3C225678A4D0935F467BC6D720E` | 恶意文件 |
| `B4822EEB71C83E4AAB5DDFECFB58459E5C5E10D382A2364DA1C42621F58E119B` | 恶意文件 |

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

1. **远程控制** (CRITICAL): config_update
2. **广告欺诈** (MEDIUM): 发现
3. **蠕虫传播** (HIGH): 发现
