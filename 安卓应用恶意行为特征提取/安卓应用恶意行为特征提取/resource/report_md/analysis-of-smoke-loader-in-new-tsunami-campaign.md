# ___ On November 8th, the Japanese Meteorological Agency issued an alert about a - 分析报告

> **来源**: FireEye
> **发布日期**: Oct 30, 2018
> **作者**: of malware keep updating the code to exp
> **恶意软件名称**: ___ On November 8th, the Japanese Meteorological Agency issued an alert about a
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 日本, 俄罗斯, 土耳其
| 活动时间 | 未知
| 传播方式 | 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
___ On November 8th, the Japanese Meteorological Agency issued an alert about a fake tsunami warning email masquerading as coming from the agency. According to the alert,
the email was written in Japanese and asked recipients to click the link to confirm their evacuation area from a tsunami after an earthquake. The link in the email is not
Smoke Loader various
critical information to save your life but malware to steal crucial information from you. The malware is , infamous commodity malware used by
cybercriminals since 2011
.
Smoke Loader is a modular loader where attackers can selec

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: account

___ On November 8th, the Japanese Meteorological Agency issued an alert about a fake tsunami warning email masquerading as coming from the agency. According to the alert,
the email was written in Japanese and asked recipients to click the link to confirm their evacuation area from a tsunami after an earthquake. The link in the email is not
Smoke Loader various
critical information to save your life but malware to steal crucial information from you. The malware is , infamous commodity malware used by
cybercriminals since 2011
.
Smoke Loader is a modular loader where attackers can select any payload to be installed on the victim by Smoke Loader. Thus, the final payload can vary between attacks. For

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

Changes the algorithm of generating the unique ID
Encrypts network traffics and payload file
FireEye Talos
Some of these techniques were already reported by and this year. We will focus on the unique ID, C2 communication, and the payload in this blog.
Generating a unique ID
Initially, the threat generates a unique ID for the compromised machine from the computer name, the hardcoded static number(0B0D0406), and the volume serial number of
the system drive. Smoke Loader uses the unique ID for three purposes:

### 3.3 银行木马 (**CRITICAL**)

cybercriminals since 2011
.
Smoke Loader is a modular loader where attackers can select any payload to be installed on the victim by Smoke Loader. Thus, the final payload can vary between attacks. For
Retefe Banking Trojan being distributed by Smoke Loader in Sweden, and Japan
example, we previously reported on the . We have also seen backdoors, ransomware,
cryptominers, password stealers, Point-of-Sale (PoS) malware, and banking Trojans installed by Smoke Loader.
This attack seems to be aiming to steal credentials from unidentified targets in Japan and took a similar approach to normal targeted attacks. The attacker registered the fake

cybercriminals since 2011
.
Smoke Loader is a modular loader where attackers can select any payload to be installed on the victim by Smoke Loader. Thus, the final payload can vary between attacks. For
Retefe Banking Trojan being distributed by Smoke Loader in Sweden, and Japan
example, we previously reported on the . We have also seen backdoors, ransomware,
cryptominers, password stealers, Point-of-Sale (PoS) malware, and banking Trojans installed by Smoke Loader.
This attack seems to be aiming to steal credentials from unidentified targets in Japan and took a similar approach to normal targeted attacks. The attacker registered the fake

### 3.4 C2 反检测 (**HIGH**)

Though it’s been seven years since Smoke Loader first appeared, the author keeps updating the code. published an excellent analysis of Smoke Loader in 2016.
The samples we looked at added the following techniques to avoid detection or analysis.
Code obfuscation by junk jump
Decrypts subroutines and encrypts them after execution
PROPagate
Employs trick to inject second stage code into an explorer.exe process
Copyright © 2025 Palo Alto Networks. All Rights Reserved

a new variant
customers. As we detailed in this article, Smoke Loader encrypts network traffic and files with various keys to avoid analysis. We recently published a report of
of AzoRult
that introduces a new advanced obfuscation technique to evade detection by security products. Attackers, like those in this tsunami campaign, can pick up
malware fitting for their purpose from online threat marketplaces.
Copyright © 2025 Palo Alto Networks. All Rights Reserved

### 3.5 勒索软件 (**HIGH**)

.
Smoke Loader is a modular loader where attackers can select any payload to be installed on the victim by Smoke Loader. Thus, the final payload can vary between attacks. For
Retefe Banking Trojan being distributed by Smoke Loader in Sweden, and Japan
example, we previously reported on the . We have also seen backdoors, ransomware,
cryptominers, password stealers, Point-of-Sale (PoS) malware, and banking Trojans installed by Smoke Loader.
This attack seems to be aiming to steal credentials from unidentified targets in Japan and took a similar approach to normal targeted attacks. The attacker registered the fake
Japanese government agency domain and ensured the file path to the malware on the server is close to the legitimate agency web site. They wrote the lure email in fluent

### 3.6 广告欺诈 (**MEDIUM**)

[Page 1]
___ On November 8th, the Japanese Meteorological Agency issued an alert about a fake tsunami warning email masquerading as coming from the agency. According to the alert,
the email was written in Japanese and asked recipients to click the link to confirm their evacuation area from a tsunami after an earthquake. The link in the email is not
Smoke Loader various
critical information to save your life but malware to steal crucial information from you. The malware is , infamous commodity malware used by
cybercriminals since 2011

### 3.7 蠕虫传播 (**HIGH**)

The samples we looked at added the following techniques to avoid detection or analysis.
Code obfuscation by junk jump
Decrypts subroutines and encrypts them after execution
PROPagate
Employs trick to inject second stage code into an explorer.exe process
Copyright © 2025 Palo Alto Networks. All Rights Reserved

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `101.226.79` | 域名类型 |
| `144.76.133` | 域名类型 |
| `149.129.135` | 域名类型 |
| `169.239.202` | 域名类型 |
| `185.121.177` | 域名类型 |
| `188.165.200` | 域名类型 |
| `192.71.245` | 域名类型 |
| `193.183.98` | 域名类型 |
| `47.74.255` | 域名类型 |
| `5.135.183` | 域名类型 |
| `51.254.25` | 域名类型 |
| `51.255.48` | 域名类型 |
| `58.251.121` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `0db3fd1394b15b98f4e112102cdec6cc569062cdb199b66c5838c54cbc286277` | 恶意文件 |
| `254925e47fbfff4786eada6cbcb0805ed79d9bd417955c016236143eb2ecd827` | 恶意文件 |
| `27aa9cdf60f1fbff84ede0d77bd49677ec346af050ffd90a43b8dcd528c9633b` | 恶意文件 |
| `3d75eabb8460450a49e2fb68053d9f591efe5aefd379205e5cc3af574bb9f415` | 恶意文件 |
| `42fdaffdbacfdf85945bd0e8bfaadb765dde622a0a7268f8aa70cd18c91a0e85` | 恶意文件 |
| `55ae2b00234674d82dcc401a0daa97e7b3921057a07970347815d9c50dddbda8` | 恶意文件 |
| `70900b5777ea48f4c635f78b597605e9bdbbee469b3052f1bd0088a1d18f85d3` | 恶意文件 |
| `7337143e5fb7ecbdf1911e248d73c930a81100206e8813ad3a90d4dd69ee53c7` | 恶意文件 |
| `748c94bfdb94b322c876114fcf55a6043f1cd612766e8af1635218a747f45fb9` | 恶意文件 |
| `75edaae605622e056a40c2d8a16b86654d7ddc772f12c4fc64292a32a96fde7a` | 恶意文件 |
| `8a1aab36c3940e4dd83f489432fa710fba582e254c3a52459c52826d6a822f2d` | 恶意文件 |
| `a1ce72ec2f2fe6139eb6bb35b8a4fb40aca2d90bc19872d6517a6ebb66b6b139` | 恶意文件 |
| `be3817b9f14df3e0af82ae47b0904ac38d022e2b2d7bb7f8f9800b534b60183c` | 恶意文件 |
| `fb3def9c23ba81f85aae0f563f4156ba9453c2e928728283de4abdfb5b5f426f` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): account
2. **远程控制** (CRITICAL): config_update
3. **银行木马** (CRITICAL): 发现
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
8. 其他行为见详细信息...
