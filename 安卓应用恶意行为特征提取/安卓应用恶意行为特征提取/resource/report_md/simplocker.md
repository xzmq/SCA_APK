# ESET Analyzes Simplocker - First - 分析报告

> **来源**: Sophos
> **发布日期**: 未知
> **作者**: to continue these kinds of filthy operat
> **恶意软件名称**: ESET Analyzes Simplocker - First
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 俄罗斯
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
ESET Research
ESET Analyzes Simplocker - First
Android File-Encrypting, TOR-enabled
Ransomware
Last weekend saw the (somewhat anticipated) discovery of an interesting mobile trojan – the
first spotting of a file-encrypting ransomware for Android by our detection engineers.
Robert Lipovsky
04 Jun 2014 • 4 min. read
[Page 2]
Update: Our developers have created ESET Simplocker Decryptor, an easy-to-use tool to decrypt files that
have been encrypted by Simplocker.
To install the application, please download it from Virus Radar with your device or scan the QR code below.
To install the app

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

[Page 6]
Files encrypted by Android/Simplock.A
Android/Simplocker.A will also contact its Command & Control server and send identifiable
information from the device (like IMEI, et cetera). Interestingly, the C&C server is hosted on a TOR
.onion domain for purposes of protection and anonymity.
Figure 3 - Part of the Android/Simplocker.A source code for connecting to the TOR anonymity network
As you may notice on the nag-screen above, there is no input field for a payment-confirming code

[Page 6]
Files encrypted by Android/Simplock.A
Android/Simplocker.A will also contact its Command & Control server and send identifiable
information from the device (like IMEI, et cetera). Interestingly, the C&C server is hosted on a TOR
.onion domain for purposes of protection and anonymity.
Figure 3 - Part of the Android/Simplocker.A source code for connecting to the TOR anonymity network

[Page 6]
Files encrypted by Android/Simplock.A
Android/Simplocker.A will also contact its Command & Control server and send identifiable
information from the device (like IMEI, et cetera). Interestingly, the C&C server is hosted on a TOR
.onion domain for purposes of protection and anonymity.
Figure 3 - Part of the Android/Simplocker.A source code for connecting to the TOR anonymity network

### 3.3 银行木马 (**CRITICAL**)

[Page 4]
Figure 1 - Android/Simplocker.A ransom message
The ransom message is written in Russian and the payment demanded in Ukrainian hryvnias, so it’s
fair to assume that the threat is targeted against this region. This is not surprising, the very first
Android SMS trojans (including Android/Fakeplayer) back in 2010 also originated from Russia and
Ukraine. The message roughly translates to:

### 3.4 C2 反检测 (**HIGH**)

[Page 1]
ESET Research
ESET Analyzes Simplocker - First
Android File-Encrypting, TOR-enabled
Ransomware
Last weekend saw the (somewhat anticipated) discovery of an interesting mobile trojan – the
first spotting of a file-encrypting ransomware for Android by our detection engineers.

### 3.5 勒索软件 (**HIGH**)

ESET Research
ESET Analyzes Simplocker - First
Android File-Encrypting, TOR-enabled
Ransomware
Last weekend saw the (somewhat anticipated) discovery of an interesting mobile trojan – the
first spotting of a file-encrypting ransomware for Android by our detection engineers.
Robert Lipovsky

trojan, detected by ESET as Android/Simplocker. This malware, after setting foot on an Android
device, scans the SD card for certain file types, encrypts them, and demands a ransom in order to
decrypt the files. Let’s look at the malware in greater detail.
After launch, the trojan will display the following ransom message and encrypt files in a separate
thread in the background.

[Page 3]

### 3.7 蠕虫传播 (**HIGH**)

Figure 1 - Android/Simplocker.A ransom message
The ransom message is written in Russian and the payment demanded in Ukrainian hryvnias, so it’s
fair to assume that the threat is targeted against this region. This is not surprising, the very first
Android SMS trojans (including Android/Fakeplayer) back in 2010 also originated from Russia and
Ukraine. The message roughly translates to:
"WARNING your phone is locked!
The device is locked for viewing and distribution child pornography , zoophilia and other perversions.

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **银行木马** (CRITICAL): 发现
3. **C2 反检测** (HIGH): 发现
4. **勒索软件** (HIGH): 发现
5. **蠕虫传播** (HIGH): 发现
