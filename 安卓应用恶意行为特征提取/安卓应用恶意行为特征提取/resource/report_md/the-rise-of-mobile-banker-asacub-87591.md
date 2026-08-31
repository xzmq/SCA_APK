# The rise of mobile banker Asacub - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: TATYANA SHISHKOVA
> **恶意软件名称**: The rise of mobile banker Asacub
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯, 土耳其
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
The rise of mobile banker Asacub
MALWARE DESCRIPTIONS 28 AUG 2018 7 minute read
// AUTHORS
TATYANA SHISHKOVA
We encountered the Trojan-Banker.AndroidOS.Asacub family for the first time in 2015, when the
first versions of the malware were detected, analyzed, and found to be more adept at spying than
stealing funds. The Trojan has evolved since then, aided by a large-scale distribution campaign by
its creators (in spring-summer 2017), helping Asacub to claim top spots in last year’s ranking by
number of attacks among mobile banking Trojans, outperforming other families such as Svpeng
an

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

TATYANA SHISHKOVA
We encountered the Trojan-Banker.AndroidOS.Asacub family for the first time in 2015, when the
first versions of the malware were detected, analyzed, and found to be more adept at spying than
stealing funds. The Trojan has evolved since then, aided by a large-scale distribution campaign by
its creators (in spring-summer 2017), helping Asacub to claim top spots in last year’s ranking by
number of attacks among mobile banking Trojans, outperforming other families such as Svpeng
and Faketoken.

### 3.2 远程控制 (**CRITICAL**)

[Page 3]
2016 version, the value of the User-Agent header changed, as did the method of generating the
relative path in the URL: now the part before /index.php is a mix of a pronounceable (if not entirely
meaningful) word and random letters and numbers, for example, “muromec280j9tqeyjy5sm1qy71” or
“parabbelumf8jgybdd6w0qa0”. Moreover, incoming traffic from the C&C server began to use gzip
compression, and the top-level domain for all C&Cs was .com:
Since December 2016, the changes in C&C communication methods have affected only how the

The name Asacub appeared with version 4 in late 2015; previous versions were known as Trojan-
SMS.AndroidOS.Smaps. Versions 5.X.X-8.X.X were active in 2016, and versions 9.X.X-1.X.X in 2017. In
2018, the most actively distributed versions were 5.0.0 and 5.0.3.
Communication with C&C
Although Asacub’s capabilities gradually evolved, its network behavior and method of
communication with the command-and-control (C&C) server changed little. This strongly
suggested that the banking Trojans, despite differing in terms of capability, belong to the same

2018, the most actively distributed versions were 5.0.0 and 5.0.3.
Communication with C&C
Although Asacub’s capabilities gradually evolved, its network behavior and method of
communication with the command-and-control (C&C) server changed little. This strongly
suggested that the banking Trojans, despite differing in terms of capability, belong to the same
family.
Data was always sent to the C&C server via HTTP in the body of a POST request in encrypted

2018, the most actively distributed versions were 5.0.0 and 5.0.3.
Communication with C&C
Although Asacub’s capabilities gradually evolved, its network behavior and method of
communication with the command-and-control (C&C) server changed little. This strongly
suggested that the banking Trojans, despite differing in terms of capability, belong to the same
family.
Data was always sent to the C&C server via HTTP in the body of a POST request in encrypted

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: app_replace, phishing

first versions of the malware were detected, analyzed, and found to be more adept at spying than
stealing funds. The Trojan has evolved since then, aided by a large-scale distribution campaign by
its creators (in spring-summer 2017), helping Asacub to claim top spots in last year’s ranking by
number of attacks among mobile banking Trojans, outperforming other families such as Svpeng
and Faketoken.

[Page 2]

[Page 1]
The rise of mobile banker Asacub
MALWARE DESCRIPTIONS 28 AUG 2018 7 minute read
// AUTHORS
TATYANA SHISHKOVA

### 3.4 C2 反检测 (**HIGH**)

communication with the command-and-control (C&C) server changed little. This strongly
suggested that the banking Trojans, despite differing in terms of capability, belong to the same
family.
Data was always sent to the C&C server via HTTP in the body of a POST request in encrypted
form to the relative address /something/index.php. In earlier versions, the something part of the
relative path was a partially intelligible, yet random mix of words and short combinations of letters
and numbers separated by an underscore, for example, “bee_bomb” or “my_te2_mms”.

### 3.5 勒索软件 (**HIGH**)

variant
Example of encrypting strings in the Trojan
Ymir: new stealthy
Asacub distribution geography ransomware in the wild
QSC:Amulti-plugin

[Page 14]

### 3.7 蠕虫传播 (**HIGH**)

After installation, the Trojan starts communicating with the cybercriminals’ C&C server. All data is
transmitted in JSON format (after decryption). It includes information about the smartphone
model, the OS version, the mobile operator, and the Trojan version.
Let’s take an in-depth look at Asacub 5.0.3, the most widespread version in 2018.
Structure of data sent to the server:
1 {
2 "type":int,

{“data”:”2015:10:14_02:41:15″,”id”:”532bf15a-b784-47e5-92fa-
72198a2929f5″,”text”:”SSB0aG91Z2h0IHdlIGdvdCBwYXN0IHRoaXMhISBJJ20gbm90I
Gh1bmdyeSBhbmQgbmU=”,”number”:”1790″,”type”:”load”}
Propagation
The banking Trojan is propagated via phishing SMS containing a link and an offer to view a photo or
MMS. The link points to a web page with a similar sentence and a button for downloading the APK
file of the Trojan to the device.

Sewn into the body of the Trojan is the version number, consisting of two or three digits separated
by periods. The numbering seems to have started anew after the version 9.
The name Asacub appeared with version 4 in late 2015; previous versions were known as Trojan-
SMS.AndroidOS.Smaps. Versions 5.X.X-8.X.X were active in 2016, and versions 9.X.X-1.X.X in 2017. In
2018, the most actively distributed versions were 5.0.0 and 5.0.3.
Communication with C&C
Although Asacub’s capabilities gradually evolved, its network behavior and method of

### 3.8 权限滥用 (**HIGH**)

device settings.
Infection
During installation, depending on the version of the Trojan, Asacub prompts the user either for
Device Administrator rights or for permission to use AccessibilityService. After receiving the rights,
it sets itself as the default SMS app and disappears from the device screen. If the user ignores or
rejects the request, the window reopens every few seconds.

[Page 17]
// REPORTS
HoneyMyte updates CoolClient and The HoneyMyte APT evolves with a kernel-
deploys multiple stealers in recent mode rootkit and a ToneShell backdoor
campaigns
Kaspersky discloses a 2025 HoneyMyte (aka
Kaspersky researchers analyze updated Mustang Panda or Bronze President) APT

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `155.133.82.181` | 域名类型 |
| `155.133.82.240` | 域名类型 |
| `155.133.82.244` | 域名类型 |
| `185.174.173.31` | 域名类型 |
| `185.234.218.59` | 域名类型 |
| `188.166.156.110` | 域名类型 |
| `195.22.126.160` | 域名类型 |
| `195.22.126.163` | 域名类型 |
| `195.22.126.80` | 域名类型 |
| `195.22.126.81` | 域名类型 |
| `195.22.126.82` | 域名类型 |
| `195.22.126.83` | 域名类型 |
| `5.45.73.24` | 域名类型 |
| `5.45.74.130` | 域名类型 |
| `mms.img.photo_` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `155.133.82.181` | 服务器 |
| `155.133.82.240` | 服务器 |
| `155.133.82.244` | 服务器 |
| `185.174.173.31` | 服务器 |
| `185.234.218.59` | 服务器 |
| `188.166.156.110` | 服务器 |
| `195.22.126.160` | 服务器 |
| `195.22.126.163` | 服务器 |
| `195.22.126.80` | 服务器 |
| `195.22.126.81` | 服务器 |
| `195.22.126.82` | 服务器 |
| `195.22.126.83` | 服务器 |
| `5.45.73.24` | 服务器 |
| `5.45.74.130` | 服务器 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `27cea60e23b0f62b4b131da29fdda916bc4539c34bb142fb6d3f8bb82380fe4c` | 恶意文件 |
| `31edacd064debdae892ab0bc788091c58a03808997e11b6c46a6a5de493ed25d` | 恶意文件 |
| `38dcec47e2f4471b032a8872ca695044ddf0c61b9e8d37274147158f689d65b9` | 恶意文件 |
| `3aedbe7057130cf359b9b57fa533c2b85bab9612c34697585497734530e7457d` | 恶意文件 |
| `87ffec0fe0e7a83e6433694d7f24cfde2f70fc45800aa2acb8e816ceba428951` | 恶意文件 |
| `c0cfd462ab21f6798e962515ac0c15a92036edd3e2e63639263bf2fd2a10c184` | 恶意文件 |
| `d791e0ce494104e2ae0092bb4adc398ce740fef28fa2280840ae7f61d4734514` | 恶意文件 |
| `df61a75b7cfa128d4912e5cb648cfc504a8e7b25f6c83ed19194905fef8624c8` | 恶意文件 |
| `eabc604fe6b5943187c12b8635755c303c450f718cc0c8e561df22a27264f101` | 恶意文件 |
| `f3ae6762df3f2c56b3fe598a9e3ff96ddf878c553be95bacbd192bd14debd637` | 恶意文件 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): app_replace, phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
8. 其他行为见详细信息...
