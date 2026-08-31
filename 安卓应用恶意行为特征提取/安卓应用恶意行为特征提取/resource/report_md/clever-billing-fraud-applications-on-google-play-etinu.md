# McAfee Labs APR 19, 2021 3 MIN READ - 分析报告

> **来源**: McAfee
> **发布日期**: APR 19, 2021
> **作者**: Sang Ryol Ryu and Chanung Pak
A new wave
> **恶意软件名称**: McAfee Labs APR 19, 2021 3 MIN READ
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 美国, 亚洲
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Clever Billing Fraud Applications on Google Play: Etinu
McAfee Labs APR 19, 2021 3 MIN READ
Authored by: Sang Ryol Ryu and Chanung Pak
A new wave of fraudulent apps has made its way to the Google Play store, targeting
Android users in Southwest Asia and the Arabian Peninsula as well—to the tune of more
than 700,000 downloads before detection by McAfee Mobile Research and co-operation
with Google to remove the apps.
Posing as photo editors, wallpapers, puzzles, keyboard skins, and other camera-related
apps, the malware embedded in these fraudulent apps hijack SMS message notifications

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts

responds “URL” value, the content in the URL is used instead of “2.png”. However, servers
do not always respond to the request or return the secret key.
As always, the most malicious functions reveal themselves in the final stage. The
malware hijacks the Notification Listener to steal incoming SMS messages like Android
Joker malware does, without the SMS read permission. Like a chain system, the malware
then passes the notification object to the final stage. When the notification has arisen
from the default SMS package, the message is finally sent out using WebView JavaScript

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: webview

Topics At McAfee English
.apk opens “1.png” file in the assets folder, decrypts it to “loader.dex,” and then loads the
dropped .dex. The “1.png” is encrypted using RC4 with the package name as the key. The
first payload creates HTTP POST request to the C2 server.
Interestingly, this malware uses key management servers. It requests keys from the
servers for the AES encrypted second payload, “2.png”. And the server returns the key as
the “s” value of JSON. Also, this malware has self-update function. When the server

6220 America Center Drive Free Downloads FAQs Careers
McAfee+™ Family
San Jose, CA 95002 USA
Parental Controls Renewals Contact Us
McAfee® Total
Malware Support Newsroom
Protection Firewall Community Investors

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

Topics At McAfee English
blog posts below for more information.
More from McAfee Labs
Learn to Identify and Astaroth: Banking Android Malware Think Before You Android M
Avoid Malicious Trojan Abusing Promises Energy Click: EPI PDF’s Hidden Targets In
Browser Extensions GitHub for Resilience Subsidy to Steal Extras Banking U
In this guide, you will learn by Harshil Patel and FAuinthaonrecdi ably DZeaPteang Chen Authored by: Anuradha & FAuinthaonrecdi ably I

Topics At McAfee English
blog posts below for more information.
More from McAfee Labs
Learn to Identify and Astaroth: Banking Android Malware Think Before You Android M
Avoid Malicious Trojan Abusing Promises Energy Click: EPI PDF’s Hidden Targets In
Browser Extensions GitHub for Resilience Subsidy to Steal Extras Banking U
In this guide, you will learn by Harshil Patel and FAuinthaonrecdi ably DZeaPteang Chen Authored by: Anuradha & FAuinthaonrecdi ably I

### 3.4 C2 反检测 (**HIGH**)

[Page 2]
In terms of details, the malware embedded in these apps takes advantage of dynamic
code loading. Encrypted payloads of malware appear in the assets folder associated
Products Features Resources About Us Why McAfee Support Log in
with the app, using names such as “cache.bin,” “settings.bin,” “data.droid,” or seemingly
innocuous “.png” files, as illustrated below.

### 3.6 广告欺诈 (**MEDIUM**)

blog posts below for more information.
More from McAfee Labs
Learn to Identify and Astaroth: Banking Android Malware Think Before You Android M
Avoid Malicious Trojan Abusing Promises Energy Click: EPI PDF’s Hidden Targets In
Browser Extensions GitHub for Resilience Subsidy to Steal Extras Banking U
In this guide, you will learn by Harshil Patel and FAuinthaonrecdi ably DZeaPteang Chen Authored by: Anuradha & FAuinthaonrecdi ably I
about the advantages and Prabudh Chakravorty Recently, we identified an Prabudh PDF converting MMciAnfeee C’sr Myopb

### 3.7 蠕虫传播 (**HIGH**)

than 700,000 downloads before detection by McAfee Mobile Research and co-operation
with Google to remove the apps.
Posing as photo editors, wallpapers, puzzles, keyboard skins, and other camera-related
apps, the malware embedded in these fraudulent apps hijack SMS message notifications
and then make unauthorized purchases. While apps go through a review process to
ensure that they are legitimate, these fraudulent apps made their way into the store by
submitting a clean version of the app for review and then introducing the malicious code

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.ce1ab3.app.photo.editor` | 域名类型 |
| `com.daynight.keyboard.wallpaper` | 域名类型 |
| `com.hit.camera.pip` | 域名类型 |
| `com.pip.editor.camera` | 域名类型 |
| `com.studio.keypaper2021` | 域名类型 |
| `com.super.color.hairdryer` | 域名类型 |
| `com.super.star.ringtones` | 域名类型 |
| `d1ag96m0hzoks5.cloudfront.net` | 域名类型 |
| `d1w5drh895wnkz.cloudfront.net` | 域名类型 |
| `d22g8hm4svq46j.cloudfront.net` | 域名类型 |
| `d37i64jgpubcy4.cloudfront.net` | 域名类型 |
| `d3i3wvt6f8lwyr.cloudfront.net` | 域名类型 |
| `d3puvb2n8wcn2r.cloudfront.net` | 域名类型 |
| `d3u41fvcv6mjph.cloudfront.net` | 域名类型 |
| `d45wejayb5ly8.cloudfront.net` | 域名类型 |
| `d8fkjd2z9mouq.cloudfront.net` | 域名类型 |
| `dospxvsfnk8s8.cloudfront.net` | 域名类型 |
| `org.my.favorites.up.keypaper` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `007587C4A84D18592BF4EF7AD828D5AAA7D50CADBBF8B0892590DB48CCA7487E` | 恶意文件 |
| `018B705E8577F065AC6F0EDE5A8A1622820B6AEAC77D0284852CEAECF8D8460C` | 恶意文件 |
| `08C4F705D5A7C9DC7C05EDEE3FCAD12F345A6EE6832D54B758E57394292BA651` | 恶意文件 |
| `08FA33BC138FE4835C15E45D1C1D5A81094E156EEF28D02EA8910D5F8E44D4B8` | 恶意文件 |
| `0E2ACCFA47B782B062CC324704C1F999796F5045D9753423CF7238FE4CABBFA8` | 恶意文件 |
| `50D498755486D3739BE5D2292A51C7C3D0ADA6D1A37C89B669A601A324794B06` | 恶意文件 |
| `9E688A36F02DD1B1A9AE4A5C94C1335B14D1B0B1C8901EC8C986B4390E95E760` | 恶意文件 |
| `CC2DEFEF5A14F9B4B9F27CC9F5BBB0D2FC8A729A2F4EBA20010E81A362D5560C` | 恶意文件 |

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
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到6类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts
2. **远程控制** (CRITICAL): webview
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
7. 其他行为见详细信息...
