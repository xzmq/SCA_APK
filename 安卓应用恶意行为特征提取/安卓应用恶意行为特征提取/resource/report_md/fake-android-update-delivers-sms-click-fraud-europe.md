# Fake Android Update Delivers SMS, Click Fraud in - 分析报告

> **来源**: McAfee
> **发布日期**: APR 29, 2016
> **作者**: Anuradha
> **恶意软件名称**: Fake Android Update Delivers SMS, Click Fraud in
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯, 美国, 欧洲
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Fake Android Update Delivers SMS, Click Fraud in
Europe
Carlos Castillo APR 29, 2016 6 MIN READ
kcabdeeF
Products Features Resources About Us Why McAfee Support Log in
Topics At McAfee Search English
Blog Other Blogs McAfee Labs Fake Android Update Delivers SMS, Click Fraud in Europe
[Page 2]
McAfee Mobile Research has been monitoring a mobile malware campaign targeting
users in Germany, France, and Russia since the beginning of the year. Several users have
Products Features Resources About Us Why McAfee Support Log in
complained in forums and social networks about a suspicious file w

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, device_info

More from McAfee Labs
Learn to Identify and Astaroth: Banking Android Malware Think Before You Android M
Avoid Malicious Trojan Abusing Promises Energy Click: EPI PDF’s Hidden Targets In
Browser Extensions GitHub for Resilience Subsidy to Steal Extras Banking U
In this guide, you will learn by Harshil Patel and FAuinthaonrecdi ably DZeaPteang Chen Authored by: Anuradha & FAuinthaonrecdi ably I
about the advantages and Prabudh Chakravorty Recently, we identified an Prabudh PDF converting MMciAnfeee C’sr Myopb
security risks of browser *EDITOR’S NOTE: Special active Android phishing software can be super Team discov

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

about McAfee Mobile Security, visit http://www.mcafeemobilesecurity.com.
SHA-256 hashes of the analyzed samples:
c60916b79e51182837f4833ae650b2abe2f7fce6eeb2f41f4ff248c6e1ec43a2
40c30ab35455b8920d08989d2695f04178c8145e9929ed7dbcd95acc2507faa7
5bfc6a02d594a8cc22bc4ed7b64e9986105a2a4992bd44cee18738182bafed60
e9dfb3a432d9e54d344515ff000d94be48322f2d2c4f102a6a319768b7248c0b

scree.off
user.present
If the cybercriminal knows that the user is not present (for example, screen off), the
remote server can send the command “webClick”:
The webClick command.

[Page 5]

Encrypted traffic sent to a remote server in Estonia.
Some variants of the malware were packed and, even after we unpacked of the payload,
the code was very obfuscated. After some static and dynamic analysis we were able to
learn that all the communication between the infected device and the control server is
encrypted using an RSA asymmetric encryption algorithm:
Malware generating a private key using an RSA specification.
Here is the device information that was constantly sent by the malware to the remote

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

Topics At McAfee English
More from McAfee Labs
Learn to Identify and Astaroth: Banking Android Malware Think Before You Android M
Avoid Malicious Trojan Abusing Promises Energy Click: EPI PDF’s Hidden Targets In
Browser Extensions GitHub for Resilience Subsidy to Steal Extras Banking U
In this guide, you will learn by Harshil Patel and FAuinthaonrecdi ably DZeaPteang Chen Authored by: Anuradha & FAuinthaonrecdi ably I

Topics At McAfee English
More from McAfee Labs
Learn to Identify and Astaroth: Banking Android Malware Think Before You Android M
Avoid Malicious Trojan Abusing Promises Energy Click: EPI PDF’s Hidden Targets In
Browser Extensions GitHub for Resilience Subsidy to Steal Extras Banking U
In this guide, you will learn by Harshil Patel and FAuinthaonrecdi ably DZeaPteang Chen Authored by: Anuradha & FAuinthaonrecdi ably I

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter, forum

The malware’s icon.
However, as soon as the user executes the app, the icon disappears, tricking the user into
believing that the app is no longer on the system. Meanwhile, in the background, the
malware sends encrypted data to a remote server in Estonia:
Encrypted traffic sent to a remote server in Estonia.
Some variants of the malware were packed and, even after we unpacked of the payload,
the code was very obfuscated. After some static and dynamic analysis we were able to

### 3.6 广告欺诈 (**MEDIUM**)

[Page 1]
Fake Android Update Delivers SMS, Click Fraud in
Europe
Carlos Castillo APR 29, 2016 6 MIN READ
kcabdeeF

[Page 1]
Fake Android Update Delivers SMS, Click Fraud in
Europe
Carlos Castillo APR 29, 2016 6 MIN READ
kcabdeeF

### 3.7 蠕虫传播 (**HIGH**)

[Page 1]
Fake Android Update Delivers SMS, Click Fraud in
Europe
Carlos Castillo APR 29, 2016 6 MIN READ
kcabdeeF

### 3.8 权限滥用 (**HIGH**)

Device information: Android version, model, manufacturer, browser user-agent,
device identifiers (IMEI, IMSI, android_id), locale (language/country configuration),
screen specifications, mobile network operator.
Device status: Wi-Fi connectivity, root status, battery status.
Malware settings: Version, apiKey, appId (package name), forGooglePlay.
The most recent variant, from April 20, omits sending root status and instead comes with
the setting “advertId,” suggesting that in future versions malware authors will include the

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `www.mcafeemobilesecurity.com` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `0d4ea10179d293666b637bbda385b7d9dd248dc998e5875ed2dddd0280fdff55` | 恶意文件 |
| `1593900445f84ffc225fc1399a563644a31e0963aa70bd1317195970706a7942` | 恶意文件 |
| `1980d5b3d8f1e30fdf0831fa2db059f1f1dd2dc749541ba3792e7093541e7958` | 恶意文件 |
| `29582ec3eb0fd77ed5a88d4dee68d5ad06299b014fa9d9f5acb35dd2282ae21e` | 恶意文件 |
| `2a5fba694f60a249bf78d88c73223c60b6528c231b7579f59b8d57c67605cc8f` | 恶意文件 |
| `2b32a6c4aa09209ebe203cc305ca3c6970bd6025d4604a1b7458b1a0bc7f9bf7` | 恶意文件 |
| `3c9d303e375ee3125593035d4e861ee94b2340b9778c10a9b33871aaa4d727e5` | 恶意文件 |
| `40c30ab35455b8920d08989d2695f04178c8145e9929ed7dbcd95acc2507faa7` | 恶意文件 |
| `4ece7dc532ad074837d141c245177ad4ba38215a9dee8093970cd671f998d130` | 恶意文件 |
| `5bfc6a02d594a8cc22bc4ed7b64e9986105a2a4992bd44cee18738182bafed60` | 恶意文件 |
| `69d93b6e50d7d684af932691c65ab396f8ae6da4a4081a171eb233e3d8dabffd` | 恶意文件 |
| `705aeb71b7134d747853a3e65f0bf492d0af0dc2aab73f1a7ccc66e2a773fa84` | 恶意文件 |
| `771946d95b38b8204562befd427fa45fd29fdfccb987bc0b33e796f4a1cbb5b0` | 恶意文件 |
| `95a3db31fc19a90f76a4a27ae87321b4d6b9b0122509258b5b87c1c5ee6f0e09` | 恶意文件 |
| `9c177189b981752c9cf89d5435c9d37c3b6441c02efb7d012426885747b7ac99` | 恶意文件 |
| `a9aef90cac11bc1f1635abde02be018a76ef4a876369d46349c5301c742597b3` | 恶意文件 |
| `ab8abfe7420777eeb02b8d40c2f012dcea36737ffd616deb20d926cff727fdc0` | 恶意文件 |
| `b44f7ae39cc6320a804174a5825d0f8fd74a6e519985f83397fe25bb12af99b1` | 恶意文件 |
| `c0a6ec3f8850676c875eb9a151f33c319950f6a8260c469874e5a30fea0b6643` | 恶意文件 |
| `c60916b79e51182837f4833ae650b2abe2f7fce6eeb2f41f4ff248c6e1ec43a2` | 恶意文件 |
| `d19ff00c8933e8fd23cfa1fb62615d18330fe43bc369492034f5755c69bf4f1c` | 恶意文件 |
| `e9dfb3a432d9e54d344515ff000d94be48322f2d2c4f102a6a319768b7248c0b` | 恶意文件 |
| `f2f2ebe7a709f0456a40dfba8eaf66af09fb2a9ed50845e1a5c24e8b78ddbb0c` | 恶意文件 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `http://www.mcafeemobilesecurity.com` | 钓鱼/下载 |
| `https://apkpure.com/developer/Smart%20Development%20LLC` | 钓鱼/下载 |
| `https://github.com/archon810/androidpolice/issues/69` | 钓鱼/下载 |
| `https://twitter.com/Baptouuuu` | 钓鱼/下载 |
| `https://twitter.com/Baptouuuu/status/708391947937914880` | 钓鱼/下载 |
| `https://twitter.com/arminhausf` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, device_info
2. **远程控制** (CRITICAL): config_update
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): twitter, forum
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
