# Tailor Solar - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Tailor Solar
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 中国
| 活动时间 | 未知
| 传播方式 | 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
gbhackers.
Ad
Tailor Solar
Solution Service
Pbox
Up to 180 Lumen/W, long
lasting lithium battery, proven
to last well over 10 years Open
Malware
Advanced Android Malware
Steal Users Facebook,
Twitter, Telegram,Skype
Messenger Data
ByBalaji April 4, 2018

[Page 2]
A Newly discgovebredh Aandrcoidk Troejanr wsith. Hidden Malicious code
compromise Android Phone and steal sensitive information from
victims well-known chat Messengers.
Andriod Malware is kept increasing and targeting victims around
the world using many advanced functionalities.
This Trojan distributing as com.android.boxa a

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

to last well over 10 years Open
Malware
Advanced Android Malware
Steal Users Facebook,
Twitter, Telegram,Skype
Messenger Data
ByBalaji April 4, 2018

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

module including “coso”, “dmnso”, “sx”, “sy”, the malware uses the
first byte in the module to XOR decrypt the data.
After the complete infection, Malware will establish the connection
with its command and control server which is operated by the
attacker.
Later it shares the collected information once the malware gets the
specific command from the attacker.

module including “coso”, “dmnso”, “sx”, “sy”, the malware uses the
first byte in the module to XOR decrypt the data.
After the complete infection, Malware will establish the connection
with its command and control server which is operated by the
attacker.
Later it shares the collected information once the malware gets the
specific command from the attacker.

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

[Page 3]
According tog trubstlohoka resceakrche, Thre sma.lware attempts to hide the
strings to avoid being detected. For example, the following strings
are stored in arrays and are XOR encrypted with 24 to get the real
strings.
Also under the folder name called Assets contains an encrypted
module and the all the module are completely encrypted and this

Advanced Functionalities of
This Android Trojan
This Malware using A lot of advanced functionalities such as anti-
emulator and debugger detection techniques to evade dynamic
analysis.
This Malicious app contains a lot of obfuscation function with the
configured file and The purpose of the content/file obfuscation is to

### 3.7 蠕虫传播 (**HIGH**)

Advanced Android Malware
Steal Users Facebook,
Twitter, Telegram,Skype
Messenger Data
ByBalaji April 4, 2018


---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.android.boxa` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): 发现
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): twitter
4. **蠕虫传播** (HIGH): 发现
