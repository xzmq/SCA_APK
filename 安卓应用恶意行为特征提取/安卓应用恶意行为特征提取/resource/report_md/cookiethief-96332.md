# Cookiethief: a cookie-stealing Trojan for Android - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: ANTON KIVVA IGOR GOLOVIN
> **恶意软件名称**: Cookiethief: a cookie-stealing Trojan for Android
> **厂商检测名**: `detect com.lob.roblox`

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
Cookiethief: a cookie-stealing Trojan for Android
12 MAR 2020 2 minute read
// AUTHORS
ANTON KIVVA IGOR GOLOVIN
We recently discovered a new strain of Android malware. The Trojan (detected as: Trojan-
Spy.AndroidOS.Cookiethief) turned out to be quite simple. Its main task was to acquire root rights
on the victim device, and transfer cookies used by the browser and Facebook app to the
cybercriminals’ server. This abuse technique is possible not because of a vulnerability in Facebook
app or browser itself. Malware could steal cookie files of any website from other apps in the same
way a

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: account

[Page 1]
Cookiethief: a cookie-stealing Trojan for Android
12 MAR 2020 2 minute read
// AUTHORS
ANTON KIVVA IGOR GOLOVIN

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

Proxy.AndroidOS.Youzicheng, and Bood as HEUR:Backdoor.AndroidOS.Bood.a.
IOCs
Package name MD5 C&C
com.lob.roblox 65a92baefd41eb8c1a9df6c266992730 api-resource.youzicheng[.]net
f84a43b008a25ba2ba1060b33daf14a5
c9c252362fd759742ea9766a769dbabe
org.rabbit c907d74ace51cec7cb53b0c8720063e1 api-rssocks.youzicheng[.]net

Smartphone shopaholic
An advertising dropper in
Google Play
On the C&C server we also found a page advertising services for distributing spam on social
networks and messengers, so it was not difficult to guess the motive behind the cookie-theft
operation.
But there’s still a hurdle for the spammers that prevents them from gaining instant access to

Malicious features of Trojan-Spy.AndroidOS.Cookiethief
13 MAY 2021, 1:00PM
GReAT Ideas. Balalaika Edition
To execute superuser commands, the malware connects to a backdoor installed on the same
smartphone… BORIS LARIN,DENIS LEGEZO
26 FEB 2021, 12:00PM
GReAT Ideas. Green Tea Edition

data!
Operation PowerFall: CVE-
2020-0986 and variants
By combining these two attacks, cybercriminals can gain complete control over the victim’s
account and not raise a suspicion from Facebook. These threats are only just starting to spread,
and the number of victims, according to our data, does not exceed 1000, but the figure is growing.
Through the C&C server addresses and encryption keys used, Cookiethief can be linked with such

### 3.4 C2 反检测 (**HIGH**)

IT threat evolution Q3 2020
The downloaded file is then run.
Targeted ransomware: it’s not
just about encrypting your
data!
Operation PowerFall: CVE-
2020-0986 and variants

### 3.5 勒索软件 (**HIGH**)

your personal data end up?
IT threat evolution Q3 2020
The downloaded file is then run.
Targeted ransomware: it’s not
just about encrypting your
data!
Operation PowerFall: CVE-

### 3.6 广告欺诈 (**MEDIUM**)

[Page 5]
Pig in a poke: smartphone
adware
Aggressive in-app advertising
in Android
Unkillable xHelper and a

### 3.7 蠕虫传播 (**HIGH**)

Operation PowerFall: CVE-
2020-0986 and variants
By combining these two attacks, cybercriminals can gain complete control over the victim’s
account and not raise a suspicion from Facebook. These threats are only just starting to spread,
and the number of victims, according to our data, does not exceed 1000, but the figure is growing.
Through the C&C server addresses and encryption keys used, Cookiethief can be linked with such
widespread Trojans as Sivu, Triada, and Ztorg. Usually, such malware is either planted in the device

An advertising dropper in
Google Play
On the C&C server we also found a page advertising services for distributing spam on social
networks and messengers, so it was not difficult to guess the motive behind the cookie-theft
operation.
But there’s still a hurdle for the spammers that prevents them from gaining instant access to
accounts just like that. For example, if Facebook detects an atypical user activity, the account may

### 3.8 权限滥用 (**HIGH**)

// AUTHORS
ANTON KIVVA IGOR GOLOVIN
We recently discovered a new strain of Android malware. The Trojan (detected as: Trojan-
Spy.AndroidOS.Cookiethief) turned out to be quite simple. Its main task was to acquire root rights
on the victim device, and transfer cookies used by the browser and Facebook app to the
cybercriminals’ server. This abuse technique is possible not because of a vulnerability in Facebook
app or browser itself. Malware could steal cookie files of any website from other apps in the same

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.lob.roblox` | 域名类型 |
| `com.roblox.client` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): account
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): 发现
4. **勒索软件** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
