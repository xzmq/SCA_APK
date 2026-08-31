# Ztorg: from rooting to SMS - 分析报告

> **来源**: 未知
> **发布日期**: May 15, 2017
> **作者**: Allow all cookies
> **恶意软件名称**: Ztorg: from rooting to SMS
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Ztorg: from rooting to SMS
MALWARE DESCRIPTIONS 20 JUN 2017 6 minute read
This website uses cookies
We use cookies to personalise content and ads, to provide social media features and to analyse our traffic. We also share information about your use of our site with our social media,
advertising and analytics partners who may combine it with other information that you’ve provided to them or that they’ve collected from your use of their services.
Show details
// AUTHORS Allow all cookies
ROMAN UNUCHEK
Customize
I’ve been monitoring Google Play Store for new Ztorg Trojans since September

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, account

countries that I tried I received files with some functions. All the files contain a function called Show details
“getAocPage” which most likely references AoC – Advice of Charge. After analyzing these files, I
found out that their main purpose is to perform clickjacking attacks on web pages with WAP billing.
In doing so, the Trojan can steal money from the user’s mobile account. WAP billing works in a similar
way to Premium rate SMS, but usually in the form of subscriptions and not one-time payments as
most Premium rate SMS.

### 3.2 远程控制 (**CRITICAL**)

MD5
F1EC3B4AD740B422EC33246C51E4782F
Show details
E448EF7470D1155B19D3CAC2E013CA0F
55366B684CE62AB7954C74269868CD91
A44A9811DB4F7D39CAC0765A5E1621AC
1142C1D53E4FBCEFC5CCD7A6F5DC7177

Trojan-SMS.AndroidOS.Ztorg.a on Google Play Store
What can they do?
After starting, the Trojan will wait for 10 minutes before connecting to its command and control
(C&C) server. It uses an interesting technique to get commands from the C&C: it makes two GET
requests to the C&C, and in both includes part of the International Mobile Subscriber Identity
(IMSI). The first request will look like this:
GET c.phaishey.com/ft/x250_c.txt, where 250 – first three digits of the IMSI.

Show details
Trojan-SMS.AndroidOS.Ztorg.a on Google Play Store
What can they do?
After starting, the Trojan will wait for 10 minutes before connecting to its command and control
(C&C) server. It uses an interesting technique to get commands from the C&C: it makes two GET
requests to the C&C, and in both includes part of the International Mobile Subscriber Identity
(IMSI). The first request will look like this:

Show details
Trojan-SMS.AndroidOS.Ztorg.a on Google Play Store
What can they do?
After starting, the Trojan will wait for 10 minutes before connecting to its command and control
(C&C) server. It uses an interesting technique to get commands from the C&C: it makes two GET
requests to the C&C, and in both includes part of the International Mobile Subscriber Identity
(IMSI). The first request will look like this:

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

Ztorg Trojan, but without the possibility of decrypting and executing it. On the following day they distribution channels
finally updated their app with the Trojan-SMS functionality, but still didn’t add the possibility to
execute the encrypted Ztorg module. It is likely that, if the app hadn’t been removed from Google
Play, they would have added this functionality at the next stage. There is also the possibility that Download a banker to track
attempting to add this functionality is what alerted Google to the Trojan’s presence and resulted in your parcel
its deletion.
Analysis of Elpaco: a Mimic

“getAocPage” which most likely references AoC – Advice of Charge. After analyzing these files, I
found out that their main purpose is to perform clickjacking attacks on web pages with WAP billing.
In doing so, the Trojan can steal money from the user’s mobile account. WAP billing works in a similar
way to Premium rate SMS, but usually in the form of subscriptions and not one-time payments as
most Premium rate SMS.

[Page 6]

### 3.4 C2 反检测 (**HIGH**)

code) and the fourth and fifth digits are the MNC (mobile network code). Using these digits, the
cybercriminals can identify the country and mobile operator of the infected user. They need this to
choose which premium rate SMS should be sent.
In answer to these requests, the Trojan may receive an encrypted JSON file with some data. This
data should include a list of offers, and every offer carries a string field called ‘url’, which may or may
not contain an actual url. The Trojan will try to open/view the field using its own class. If this value is
indeed a url, the Trojan will show its content to the user. But if it is something else and carries an

### 3.5 勒索软件 (**HIGH**)

We found a very unusual Trojan-SMS being distributed through Google Play. It not only uses around
a dozen methods to send SMS, but also initializes these methods in an unusual way: by processing
Ymir: new stealthy
ransomwareinthewild

[Page 9]
ransomware in the wild

### 3.6 广告欺诈 (**MEDIUM**)

with users from a different countries. I wasn’t able to get a file for a US MCC, but for other
countries that I tried I received files with some functions. All the files contain a function called Show details
“getAocPage” which most likely references AoC – Advice of Charge. After analyzing these files, I
found out that their main purpose is to perform clickjacking attacks on web pages with WAP billing.
In doing so, the Trojan can steal money from the user’s mobile account. WAP billing works in a similar
way to Premium rate SMS, but usually in the form of subscriptions and not one-time payments as
most Premium rate SMS.

### 3.7 蠕虫传播 (**HIGH**)

[Page 1]
Ztorg: from rooting to SMS
MALWARE DESCRIPTIONS 20 JUN 2017 6 minute read
This website uses cookies
We use cookies to personalise content and ads, to provide social media features and to analyse our traffic. We also share information about your use of our site with our social media,

### 3.8 权限滥用 (**HIGH**)

Trojan along with the other Ztorg modules. And it isn’t the first case where additional Ztorg
modules were distributed from Google Play as a standalone Trojan. In April 2017, I found that a
malicious app called “Money Converter”, had been installed more than 10,000 times from Google
Play. It uses Accessibility Services to install apps from Google Play. Therefore, the Trojan can
silently install and run promoted apps without any interaction with the user, even on updated
devices where it cannot gain root rights.
Trojan-SMS vs. rooting

[Page 1]
Ztorg: from rooting to SMS
MALWARE DESCRIPTIONS 20 JUN 2017 6 minute read
This website uses cookies
We use cookies to personalise content and ads, to provide social media features and to analyse our traffic. We also share information about your use of our site with our social media,

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `c.phaishey.com` | 域名类型 |
| `down.rbksbtmk.com` | 域名类型 |
| `global.621.co` | 域名类型 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `http://down.rbksbtmk.com/pic/four-dault-` | 钓鱼/下载 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
