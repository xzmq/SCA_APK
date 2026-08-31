# botnet discovered - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: ities
> **恶意软件名称**: botnet discovered
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等)
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
First Twitter-controlled Android
botnet discovered
Detected by ESET as Android/Twitoor, this malware is unique because of its resilience
mechanism. Instead of being controlled by a traditional command-and-control server, it
receives instructions via tweets.
Editor
24 Aug 2016 • 2 min. read
[Page 2]
Android/Twitoor is a backdoor capable of downloading other malware onto an infected device. It
has been active for around one month. This malicious app, detected by ESET as a variant of
Android/Twitoor.A, can’t be found on any official Android app store – it probably spreads by SMS or
via m

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

functionality.
After launching, it hides its presence on the system and checks the defined Twitter account at
regular intervals for commands. Based on received commands, it can either download malicious
apps or switch the C&C Twitter account to another one.
“Using Twitter instead of command-and-control (C&C)
“Using Twitter
servers is pretty innovative for an Android botnet,” says

First Twitter-controlled Android
botnet discovered
Detected by ESET as Android/Twitoor, this malware is unique because of its resilience
mechanism. Instead of being controlled by a traditional command-and-control server, it
receives instructions via tweets.
Editor
24 Aug 2016 • 2 min. read

[Page 1]
First Twitter-controlled Android
botnet discovered
Detected by ESET as Android/Twitoor, this malware is unique because of its resilience
mechanism. Instead of being controlled by a traditional command-and-control server, it

### 3.3 银行木马 (**CRITICAL**)

[Page 3]
“In the future, we can expect that the bad guys will try to make use of Facebook statuses or deploy
LinkedIn and other social networks”, states ESET’s researcher.
Currently, the Twitoor trojan has been downloading several versions of mobile banking malware.
However, the botnet operators can start distributing other malware, including ransomware, at any
time warns Štefanko.
“Twitoor serves as another example of how cybercriminals keep on innovating their business,”

[Page 3]
“In the future, we can expect that the bad guys will try to make use of Facebook statuses or deploy
LinkedIn and other social networks”, states ESET’s researcher.
Currently, the Twitoor trojan has been downloading several versions of mobile banking malware.
However, the botnet operators can start distributing other malware, including ransomware, at any
time warns Štefanko.
“Twitoor serves as another example of how cybercriminals keep on innovating their business,”

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

servers get seized by the authorities, it would ultimately
lead to disclosing information about the entire botnet.
To make the Twitoor botnet’s communication more resilient, botnet designers took various steps
like encrypting their messages, using complex topologies of the C&C network – or using innovative
means for communication, among them the use of social networks.
“These communication channels are hard to discover and even harder to block entirely. On the
other hand, it’s extremely easy for the crooks to re-direct communications to another freshly

### 3.5 勒索软件 (**HIGH**)

“In the future, we can expect that the bad guys will try to make use of Facebook statuses or deploy
LinkedIn and other social networks”, states ESET’s researcher.
Currently, the Twitoor trojan has been downloading several versions of mobile banking malware.
However, the botnet operators can start distributing other malware, including ransomware, at any
time warns Štefanko.
“Twitoor serves as another example of how cybercriminals keep on innovating their business,”
Stefanko continues. “The takeaway? Internet users should keep on securing their activities with

### 3.7 蠕虫传播 (**HIGH**)

[Page 2]
Android/Twitoor is a backdoor capable of downloading other malware onto an infected device. It
has been active for around one month. This malicious app, detected by ESET as a variant of
Android/Twitoor.A, can’t be found on any official Android app store – it probably spreads by SMS or
via malicious URLs. It impersonates a porn player app or MMS application but without having their
functionality.
After launching, it hides its presence on the system and checks the defined Twitter account at

[Page 2]
Android/Twitoor is a backdoor capable of downloading other malware onto an infected device. It
has been active for around one month. This malicious app, detected by ESET as a variant of
Android/Twitoor.A, can’t be found on any official Android app store – it probably spreads by SMS or
via malicious URLs. It impersonates a porn player app or MMS application but without having their
functionality.
After launching, it hides its presence on the system and checks the defined Twitter account at

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等) |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **银行木马** (CRITICAL): 发现
3. **C2 反检测** (HIGH): twitter
4. **勒索软件** (HIGH): 发现
5. **蠕虫传播** (HIGH): 发现
