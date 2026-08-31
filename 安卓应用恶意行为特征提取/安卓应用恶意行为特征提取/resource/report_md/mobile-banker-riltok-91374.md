# Riltok mobile Trojan: A banker with global reach - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: TATYANA SHISHKOVA
> **恶意软件名称**: Riltok mobile Trojan: A banker with global reach
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
Riltok mobile Trojan: A banker with global reach
25 JUN 2019 4 minute read
// AUTHORS
TATYANA SHISHKOVA
Riltok is one of numerous families of mobile banking Trojans with standard (for such malware)
functions and distribution methods. Originally intended to target the Russian audience, the banker
was later adapted, with minimal modifications, for the European “market.” The bulk of its victims
(more than 90%) reside in Russia, with France in second place (4%). Third place is shared by Italy,
Ukraine, and the United Kingdom.
[Page 2]
Geographic spread of the Riltok banking Trojan
We firs

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

2021
C&C
100.51.100.00
Dox, steal, reveal. Where does
108.62.118.131
your personal data end up?
172.81.134.165

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

whitekalgoy3.com
youlaprotect.ru
Examples of malware
0497b6000a7a23e9e9b97472bc2d3799caf49cbbea1627ad4d87ae6e0b7e2a98
417fc112cd0610cc8c402742b0baab0a086b5c4164230009e11d34fdeee7d3fa
54594edbe9055517da2836199600f682dee07e6b405c6fe4b476627e8d184bfe
6e995d68c724f121d43ec2ff59bc4e536192360afa3beaec5646f01094f0b745

During installation, Riltok asks the user for permission to use special features in
Infection
AccessibilityService by displaying a fake warning:
Communication with C&C
Trojan anatomy
Conclusion
IoCs

Then, using POST requests to the relative address report.php, it sends data about the device (IMEI,
phone number, country, mobile operator, phone model, availability of root rights, OS version), list of
contacts, list of installed apps, incoming SMS, and other information. From the server, the Trojan
receives commands (for example, to send SMS) and changes in the configuration.

[Page 7]
Trojan anatomy

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

25 JUN 2019 4 minute read
// AUTHORS
TATYANA SHISHKOVA
Riltok is one of numerous families of mobile banking Trojans with standard (for such malware)
functions and distribution methods. Originally intended to target the Russian audience, the banker
was later adapted, with minimal modifications, for the European “market.” The bulk of its victims
(more than 90%) reside in Russia, with France in second place (4%). Third place is shared by Italy,

[Page 1]
Riltok mobile Trojan: A banker with global reach
25 JUN 2019 4 minute read
// AUTHORS
TATYANA SHISHKOVA

Icons most frequently used by the Trojan: Avito, Youla, Gumtree, Leboncoin, Subito
In November 2018, a version of the Trojan for the English market appeared in the shape of
Gumtree.apk. The SMS message with a link to a banker looked as follows: “%USERNAME%, i send
you prepayment gumtree[.]cc/3*****1”.

[Page 3]
Italian (Subito.apk) and French (Leboncoin.apk) versions appeared shortly afterwards in January

### 3.4 C2 反检测 (**HIGH**)

185.212.128.152
185.212.128.192
185.61.000.108 Targeted ransomware: it’s not
just about encrypting your
185.61.138.108 data!
185.61.138.37
188.209.52.101 Operation PowerFall: CVE-

### 3.5 勒索软件 (**HIGH**)

IT threat evolution Q3 2020
185.212.128.152
185.212.128.192
185.61.000.108 Targeted ransomware: it’s not
just about encrypting your
185.61.138.108 data!
185.61.138.37

### 3.6 广告欺诈 (**MEDIUM**)

[Page 4]
If the user ignores or declines the request, the window keeps opening ad infinitum. After obtaining
the desired rights, the Trojan sets itself as the default SMS app (by independently clicking Yes in
AccessibilityService), before vanishing from the device screen.

[Page 5]

### 3.7 蠕虫传播 (**HIGH**)

Ukraine, and the United Kingdom.

[Page 2]
Geographic spread of the Riltok banking Trojan
We first detected members of this family back in March 2018. Like many other bankers, they were
disguised as apps for popular free ad services in Russia. The malware was distributed from infected
devices via SMS in the form “%USERNAME%, I’ll buy under a secure transaction.

Geographic spread of the Riltok banking Trojan
We first detected members of this family back in March 2018. Like many other bankers, they were
disguised as apps for popular free ad services in Russia. The malware was distributed from infected
devices via SMS in the form “%USERNAME%, I’ll buy under a secure transaction.
youlabuy[.]ru/7*****3” or “%USERNAME%, accept 25,000 on Youla youla-protect[.]ru/4*****7”,
containing a link to download the Trojan. Other samples were also noticed, posing as a client of a
ticket-finding service or as an app store for Android.

### 3.8 权限滥用 (**HIGH**)

unknown sources in the device settings. Table of Contents
During installation, Riltok asks the user for permission to use special features in
Infection
AccessibilityService by displaying a fake warning:
Communication with C&C
Trojan anatomy
Conclusion

random way based on the device IMEI) and screen (shows if the device is active, possible values are
“on”, “off”, “none”) parameters.
Then, using POST requests to the relative address report.php, it sends data about the device (IMEI,
phone number, country, mobile operator, phone model, availability of root rights, OS version), list of
contacts, list of installed apps, incoming SMS, and other information. From the server, the Trojan
receives commands (for example, to send SMS) and changes in the configuration.

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `100.51.100.00` | 域名类型 |
| `108.62.118.131` | 域名类型 |
| `172.81.134.165` | 域名类型 |
| `172.86.120.207` | 域名类型 |
| `185.212.128.152` | 域名类型 |
| `185.212.128.192` | 域名类型 |
| `185.61.000.108` | 域名类型 |
| `185.61.138.108` | 域名类型 |
| `185.61.138.37` | 域名类型 |
| `188.209.52.101` | 域名类型 |
| `5.206.225.57` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `100.51.100.00` | 服务器 |
| `108.62.118.131` | 服务器 |
| `172.81.134.165` | 服务器 |
| `172.86.120.207` | 服务器 |
| `185.212.128.152` | 服务器 |
| `185.212.128.192` | 服务器 |
| `185.61.000.108` | 服务器 |
| `185.61.138.108` | 服务器 |
| `185.61.138.37` | 服务器 |
| `188.209.52.101` | 服务器 |
| `5.206.225.57` | 服务器 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `0497b6000a7a23e9e9b97472bc2d3799caf49cbbea1627ad4d87ae6e0b7e2a98` | 恶意文件 |
| `417fc112cd0610cc8c402742b0baab0a086b5c4164230009e11d34fdeee7d3fa` | 恶意文件 |
| `54594edbe9055517da2836199600f682dee07e6b405c6fe4b476627e8d184bfe` | 恶意文件 |
| `6e995d68c724f121d43ec2ff59bc4e536192360afa3beaec5646f01094f0b745` | 恶意文件 |
| `bbc268ca63eeb27e424fec1b3976bab550da304de18e29faff94d9057b1fa25a` | 恶意文件 |
| `dc3dd9d75120934333496d0a4100252b419ee8fcdab5d74cf343bcb0306c9811` | 恶意文件 |
| `e3f77ff093f322e139940b33994c5a57ae010b66668668dc4945142a81bcc049` | 恶意文件 |
| `ebd0a8043434edac261cb25b94f417188a5c0d62b5dd4033f156b890d150a4c5` | 恶意文件 |
| `f51a27163cb0ddd08caa29d865b9f238848118ba2589626af711330481b352df` | 恶意文件 |

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
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): config_update
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
