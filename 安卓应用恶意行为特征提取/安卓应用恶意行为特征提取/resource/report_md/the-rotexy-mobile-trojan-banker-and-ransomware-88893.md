# The Rotexy mobile Trojan – banker and ransomware - 分析报告

> **来源**: 未知
> **发布日期**: since 2014
> **作者**: TATYANA SHISHKOVA LEV PIKMAN
> **恶意软件名称**: The Rotexy mobile Trojan – banker and ransomware
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯, 土耳其
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
The Rotexy mobile Trojan – banker and ransomware
MALWARE DESCRIPTIONS 22 NOV 2018 9 minute read
// AUTHORS
TATYANA SHISHKOVA LEV PIKMAN
On the back of a surge in Trojan activity, we decided to carry out an in-depth analysis and track the
evolution of some other popular malware families besides Asacub. One of the most interesting and
active specimens to date was a mobile Trojan from the Rotexy family. In a three-month period from
August to October 2018, it launched over 70,000 attacks against users located primarily in Russia.
An interesting feature of this family of banking Trojans is

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account

other significant changes were observed in the Trojan’s network behavior.
Query from the Trojan to the C&C
In late 2016, versions of the Trojan emerged that contained the card.html phishing page in the
assets/www folder. The page was designed to steal users’ bank card details:

[Page 8]
2017–2018

[Page 13]
In this sample of the Trojan, the Plugs.DynamicSubDomain value is false, so subdomains are not
generated
The Trojan stores information about C&C servers and the data harvested from the infected device
in a local SQLite database.
First off, the Trojan registers in the administration panel and receives the information it needs to
operate from the C&C (the SMS interception templates and the text that will be displayed on

### 3.2 远程控制 (**CRITICAL**)

against attacks by this Trojan.
IOCs
SHA256
0ca09d4fde9e00c0987de44ae2ad51a01b3c4c2c11606fe8308a083805760ee7
4378f3680ff070a1316663880f47eba54510beaeb2d897e7bbb8d6b45de63f96
76c9d8226ce558c87c81236a9b95112b83c7b546863e29b88fec4dba5c720c0b
7cc2d8d43093c3767c7c73dc2b4daeb96f70a7c455299e0c7824b4210edd6386

mobile device via Google servers;

[Page 2]
malicious C&C server;
incoming SMS messages.
This ‘versatility’ was present in the first version of Rotexy and has been a feature of all the family’s
subsequent representatives. During our research we also arrived at the conclusion that this Trojan

evolution of some other popular malware families besides Asacub. One of the most interesting and
active specimens to date was a mobile Trojan from the Rotexy family. In a three-month period from
August to October 2018, it launched over 70,000 attacks against users located primarily in Russia.
An interesting feature of this family of banking Trojans is the simultaneous use of three command
sources:
Google Cloud Messaging (GCM) service – used to send small messages in JSON format to a
mobile device via Google servers;

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

evolution of some other popular malware families besides Asacub. One of the most interesting and
active specimens to date was a mobile Trojan from the Rotexy family. In a three-month period from
August to October 2018, it launched over 70,000 attacks against users located primarily in Russia.
An interesting feature of this family of banking Trojans is the simultaneous use of three command
sources:
Google Cloud Messaging (GCM) service – used to send small messages in JSON format to a
mobile device via Google servers;

[Page 1]
The Rotexy mobile Trojan – banker and ransomware
MALWARE DESCRIPTIONS 22 NOV 2018 9 minute read
// AUTHORS
TATYANA SHISHKOVA LEV PIKMAN

[Page 4]
In its first communication, the Trojan sent the infected device’s IMEI to the C&C, and in return it
received a set of rules for processing incoming SMSs (phone numbers, keywords and regular
expressions) – these applied mainly to messages from banks, payment systems and mobile
network operators. For instance, the Trojan could automatically reply to an SMS and immediately
delete it.

### 3.4 C2 反检测 (**HIGH**)

[Page 3]
A typical class list in the Trojan’s DEX file
Until mid-2015, Rotexy used a plain-text JSON format to communicate with its C&C. The C&C
address was specified in the code and was also unencrypted:
In some versions, a dynamically generated low-level domain was used as an address:

[Page 4]

### 3.5 勒索软件 (**HIGH**)

[Page 1]
The Rotexy mobile Trojan – banker and ransomware
MALWARE DESCRIPTIONS 22 NOV 2018 9 minute read
// AUTHORS
TATYANA SHISHKOVA LEV PIKMAN

### 3.7 蠕虫传播 (**HIGH**)

detected as Trojan-Spy.AndroidOS.SmsThief, but later versions were assigned to another family –
Trojan-Banker.AndroidOS.Rotexy.
The modern version of Rotexy combines the functions of a banking Trojan and ransomware. It
spreads under the name AvitoPay.apk (or similar) and downloads from websites with names like
youla9d6h.tk, prodam8n9.tk, prodamfkz.ml, avitoe0ys.tk, etc. These website names are generated
according to a clear algorithm: the first few letters are suggestive of popular classified ad services,
followed by a random string of characters, followed by a two-letter top-level domain. But before

like to give a summary of the path the Trojan has taken since 2014 up to the present day.
Evolution of Rotexy
2014–2015
Since the malicious program was detected in 2014, its main functions and propagation method
have not changed: Rotexy spreads via links sent in phishing SMSs that prompt the user to install an
app. As it launches, it requests device administrator rights, and then starts communicating with its
C&C server.

[Page 2]
malicious C&C server;
incoming SMS messages.
This ‘versatility’ was present in the first version of Rotexy and has been a feature of all the family’s
subsequent representatives. During our research we also arrived at the conclusion that this Trojan
evolved from an SMS spyware Trojan that was first spotted in October 2014. Back then it was

### 3.8 权限滥用 (**HIGH**)

KSENIYA KUDASHEVA FABIO ASSOLINI
// REPORTS
HoneyMyte updates CoolClient and The HoneyMyte APT evolves with a kernel-
deploys multiple stealers in recent mode rootkit and a ToneShell backdoor
campaigns
Kaspersky discloses a 2025 HoneyMyte (aka
Kaspersky researchers analyze updated Mustang Panda or Bronze President) APT

---

## 4. IoCs (威胁指标)

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `0ca09d4fde9e00c0987de44ae2ad51a01b3c4c2c11606fe8308a083805760ee7` | 恶意文件 |
| `4378f3680ff070a1316663880f47eba54510beaeb2d897e7bbb8d6b45de63f96` | 恶意文件 |
| `76c9d8226ce558c87c81236a9b95112b83c7b546863e29b88fec4dba5c720c0b` | 恶意文件 |
| `7cc2d8d43093c3767c7c73dc2b4daeb96f70a7c455299e0c7824b4210edd6386` | 恶意文件 |
| `9b2fd7189395b2f34781b499f5cae10ec86aa7ab373fbdc2a14ec4597d4799ba` | 恶意文件 |
| `ac216d502233ca0fe51ac2bb64cfaf553d906dc19b7da4c023fec39b000bc0d7` | 恶意文件 |
| `b1ccb5618925c8f0dda8d13efe4a1e1a93d1ceed9e26ec4a388229a28d1f8d5b` | 恶意文件 |
| `ba4beb97f5d4ba33162f769f43ec8e7d1ae501acdade792a4a577cd6449e1a84` | 恶意文件 |
| `ba9f4d3f4eba3fa7dce726150fe402e37359a7f36c07f3932a92bd711436f88c` | 恶意文件 |
| `e194268bf682d81fc7dc1e437c53c952ffae55a9d15a1fc020f0219527b7c2ec` | 恶意文件 |

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
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
8. 其他行为见详细信息...
