# The banker that can steal anything - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: ANTON KIVVA
> **恶意软件名称**: The banker that can steal anything
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
The banker that can steal anything
MALWARE DESCRIPTIONS 20 SEP 2016 2 minute read
// AUTHORS
ANTON KIVVA
In the past, we’ve seen superuser rights exploit advertising applications such as Leech, Guerrilla,
Ztorg. This use of root privileges is not typical, however, for banking malware attacks, because
money can be stolen in numerous other ways that don’t require exclusive rights. However, in early
February 2016, Kaspersky Lab discovered Trojan-Banker.AndroidOS.Tordow.a, whose creators
decided that root privileges would come in handy. We had been watching the development of this
malicio

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

[Page 1]
The banker that can steal anything
MALWARE DESCRIPTIONS 20 SEP 2016 2 minute read
// AUTHORS
ANTON KIVVA

### 3.2 远程控制 (**CRITICAL**)

the infected device is loaded with several malicious modules; their number and functionality also
depend on what the Tordow owners want to do. Either way, the attackers get the chance to 17 JUN 2020, 1:00PM
GReAT Ideas. Powered by SAS:
remotely control the device by sending commands from the C&C.
malware attribution and next-gen IoT
honeypots

the infected device is loaded with several malicious modules; their number and functionality also
depend on what the Tordow owners want to do. Either way, the attackers get the chance to 17 JUN 2020, 1:00PM
GReAT Ideas. Powered by SAS:
remotely control the device by sending commands from the C&C.
malware attribution and next-gen IoT
honeypots

the infected device is loaded with several malicious modules; their number and functionality also
depend on what the Tordow owners want to do. Either way, the attackers get the chance to 17 JUN 2020, 1:00PM
GReAT Ideas. Powered by SAS:
remotely control the device by sending commands from the C&C.
malware attribution and next-gen IoT
honeypots

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

// AUTHORS
ANTON KIVVA
In the past, we’ve seen superuser rights exploit advertising applications such as Leech, Guerrilla,
Ztorg. This use of root privileges is not typical, however, for banking malware attacks, because
money can be stolen in numerous other ways that don’t require exclusive rights. However, in early
February 2016, Kaspersky Lab discovered Trojan-Banker.AndroidOS.Tordow.a, whose creators
decided that root privileges would come in handy. We had been watching the development of this

[Page 1]
The banker that can steal anything
MALWARE DESCRIPTIONS 20 SEP 2016 2 minute read
// AUTHORS
ANTON KIVVA

### 3.4 C2 反检测 (**HIGH**)

KYLER
Posted on September 20, 2016. 1:26 pm
Great report, thanks for doing what you do!
The passwords in the browser database aren’t hashed or encrypted? Storing this type of critical
data without severe security protections is irresponsible.
Reply
STEVEN CHEN

### 3.5 勒索软件 (**HIGH**)

[Page 3]
As a result, cybercriminals get a full set of functions for stealing money from users by applying the MARCO PREUSS,DENIS LEGEZO,COSTIN RAIU,
methods that have already become traditional for mobile bankers and ransomware. The KURT BAUMGARTNER,DAN DEMETER,YAROSLAV SHMELEV
functionality of the malicious app includes:
26 AUG 2020, 2:00PM
Sending, stealing, deleting SMS. GReAT Ideas. Powered by SAS: threat

### 3.7 蠕虫传播 (**HIGH**)

methods that have already become traditional for mobile bankers and ransomware. The KURT BAUMGARTNER,DAN DEMETER,YAROSLAV SHMELEV
functionality of the malicious app includes:
26 AUG 2020, 2:00PM
Sending, stealing, deleting SMS. GReAT Ideas. Powered by SAS: threat
actors advance on new fronts
Recording, redirecting, blocking calls.
IVAN KWIATKOWSKI,MAHER YAMOUT,NOUSHIN SHABAB,

### 3.8 权限滥用 (**HIGH**)

// AUTHORS
ANTON KIVVA
In the past, we’ve seen superuser rights exploit advertising applications such as Leech, Guerrilla,
Ztorg. This use of root privileges is not typical, however, for banking malware attacks, because
money can be stolen in numerous other ways that don’t require exclusive rights. However, in early
February 2016, Kaspersky Lab discovered Trojan-Banker.AndroidOS.Tordow.a, whose creators
decided that root privileges would come in handy. We had been watching the development of this

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
8. 其他行为见详细信息...
