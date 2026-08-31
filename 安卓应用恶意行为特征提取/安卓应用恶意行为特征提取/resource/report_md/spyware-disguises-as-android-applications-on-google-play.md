# the world. - 分析报告

> **来源**: Trend Micro
> **发布日期**: Jan 03, 2019
> **作者**: Ecular Xu
> **恶意软件名称**: the world.
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 南非, 伊朗, 越南, 泰国
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Malware
Spyware Disguises as Android Apps on Google Play
Spyware disguised itself as legitimate Android applications to steal information from users. Some malicious apps were already downloaded over 100,000 times by users from all over
the world.
By: Ecular Xu, Grey Guo
Jan 03, 2019
Read time: 3 min (818 words)
We discovered a spyware (detected as ANDROIDOS_MOBSTSPY) which disguised itself as
legitimate Android applications to gather information from users. The applications were available
for download on Google Play in 2018, with some recorded to have already been downloaded
over 100,

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account, device_info

[Page 1]
Malware
Spyware Disguises as Android Apps on Google Play
Spyware disguised itself as legitimate Android applications to steal information from users. Some malicious apps were already downloaded over 100,000 times by users from all over
the world.
By: Ecular Xu, Grey Guo
Jan 03, 2019

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

0c477d3013ea8301145b38acd1c59969de50b7e2e7fc7c4d37fe0abc3d32d617 com[.]mobistartapp[.]flashlight FlashLight
100
Flappy Birr
a645a3f886708e00d48aca7ca6747778c98f81765324322f858fc26271026945 com[.]tassaly[.]flappybirrdog 10
Dog
Command and Control Servers
 hxxp://www[.]mobistartapp[.]com

MobSTSPY is capable of stealing information like user location, SMS conversations, call logs and
clipboard items. It uses Firebase Cloud Messaging to send information to its server. Once the
malicious application is launched, the malware will first check the device's network availability. It
then reads and parses an XML configure file from its C&C server.

[Page 4]
Figure 2. Example of configure file being taken from a C&C server

[Page 5]
It sends the gathered information to its C&C server, thus registering the device. Once done, the
malware will wait for and perform commands sent from its C&C server through FCM.

[Page 6]

Flappy Birr
a645a3f886708e00d48aca7ca6747778c98f81765324322f858fc26271026945 com[.]tassaly[.]flappybirrdog 10
Dog
Command and Control Servers
 hxxp://www[.]mobistartapp[.]com 
hxxp://www[.]coderoute[.]ma

### 3.5 勒索软件 (**HIGH**)

solution to defend their mobile devices against mobile malware.
Trend Micro Mobile Security detects such attacks, defends devices from all related threats,
and blocks malicious apps. End users can also benefit from its multilayered security capabilities
that secure the device’s data and privacy, and safeguard them from ransomware, fraudulent
websites, and identity theft.
For organizations, Trend Micro™ Mobile Security for Enterprise provides device, compliance and 
application management, data protection, and configuration provisioning, as well as protects

### 3.7 蠕虫传播 (**HIGH**)

[Page 3]
Figure 1. Flappy Birr Dog download page
Information stealing
MobSTSPY is capable of stealing information like user location, SMS conversations, call logs and
clipboard items. It uses Firebase Cloud Messaging to send information to its server. Once the
malicious application is launched, the malware will first check the device's network availability. It
then reads and parses an XML configure file from its C&C server.

---

## 4. IoCs (威胁指标)

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `0c477d3013ea8301145b38acd1c59969de50b7e2e7fc7c4d37fe0abc3d32d617` | 恶意文件 |
| `12fe6df56969070fd286b3a8e23418749b94ef47ea63ec420bdff29253a950a3` | 恶意文件 |
| `38d70644a2789fc16ca06c4c05c3e1959cb4bc3b068ae966870a599d574c9b24` | 恶意文件 |
| `4593635ba742e49a64293338a383f482f0f1925871157b5c4b1222e79909e838` | 恶意文件 |
| `72252bd4ecfbd9d701a92a71ff663776f685332a488b41be75b3329b19de66ba` | 恶意文件 |
| `a645a3f886708e00d48aca7ca6747778c98f81765324322f858fc26271026945` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **勒索软件** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
