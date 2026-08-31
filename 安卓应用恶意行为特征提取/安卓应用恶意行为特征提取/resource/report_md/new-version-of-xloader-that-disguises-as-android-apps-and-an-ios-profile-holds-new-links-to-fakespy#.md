# By: Hara Hiroaki, Lilang Wu, Lorin Wu - 分析报告

> **来源**: Trend Micro
> **发布日期**: Apr 02, 2019
> **作者**: Hara Hiroaki
> **恶意软件名称**: By: Hara Hiroaki, Lilang Wu, Lorin Wu
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 日本, 韩国
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), SMiShing (短信钓鱼), 钓鱼, 即时通讯软件传播, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Malware
XLoader Disguises as Android Apps, Has FakeSpy Links
This new XLoader variant poses as a security app for Android devices, and uses a malicious iOS profile to affect iPhone and iPad devices.
By: Hara Hiroaki, Lilang Wu, Lorin Wu
Apr 02, 2019
Read time: 6 min (1602 words)
In previous attacks, XLoader posed as Facebook, Chrome and other legitimate applications to
trick users into downloading its malicious app. Trend Micro researchers found a new variant that
uses a different way to lure users. This new XLoader variant poses as a security app for Android
devices, and uses a malic

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

403401aa71df1830d294b78de0e5e867ee3738568369c48ffafe1b15f3145588 ufD.wyjyx.vahvh 佐川急便
466dafa82a4460dcad722d2ad9b8ca332e9a896fc59f06e16ebe981ad3838a6b com.dhp.ozqh Facebook
Anshin
5022495104c280286e65184e3164f3f248356d065ad76acef48ee2ce244ffdc8 ufD.wyjyx.vahvh
Scan
a0f3df39d20c4eaa410a61a527507dbc6b17c7f974f76e13181e98225bda0511 com.aqyh.xolo 佐川急便
cb412b9a26c1e51ece7a0e6f98f085e1c27aa0251172bf0a361eb5d1165307f7 jp.co.sagawa.SagawaOfficialApp 佐川急便

in line with its new deployment method. We discuss these changes and its effect on Android and
Apple devices.
Malicious APK
Like its previous versions, XLoader 6.0 abuses social media user profiles to hide its real C&C
addresses, but this time its threat actors chose the social media platform Twitter, which was
never used in previous attacks. The real C&C address is encoded in the Twitter names, and can
only be revealed once decoded. This adds an extra layer against detection. The code for this

[Page 6]
Figure 4. Malicious Twitter pages that hide the real C&C address
Version 6.0 also adds a command called “getPhoneState”, which collects unique identifiers of
mobile devices such as IMSI, ICCID, Android ID, and device serial number. This addition is seen in
Figure 5. Considering the other malicious behaviors of XLoader, this added operation could be
very dangerous as threat actors can use it to perform targeted attacks.

will prompt the download of the APK. However, successfully installing this malicious APK requires

[Page 4]
that the user has allowed the installation of such apps as controlled in the Unknown Sources
settings. If users allow such apps to be installed, then it can be actively installed on the victim’s
device.
The infection chain is slightly more roundabout in the case of Apple devices. Accessing the same

### 3.5 勒索软件 (**HIGH**)

Users can take advantage of Trend Micro™ Mobile Security for Android™ (available on Google
Play) to block malicious apps that may exploit this vulnerability. End users and enterprises can
also benefit from its multilayered security capabilities that secure the device’s data and privacy,
and safeguard them from ransomware, fraudulent websites, and identity theft. For organizations,
Trend Micro™ Mobile Security for Enterprise provides device, compliance and application
management, data protection, and configuration provisioning. It also protects devices from
attacks that leverage vulnerabilities, prevents unauthorized access to apps, and detects and

### 3.7 蠕虫传播 (**HIGH**)

a Japanese mobile phone operator’s website in particular — to trick users into downloading the
fake security Android application package (APK). Monitoring efforts on this new variant revealed

that the malicious websites are spread through smishing. The infection has not spread very
widely at the time of writing, but we’ve seen that many users have already received its SMS
content.

fake security Android application package (APK). Monitoring efforts on this new variant revealed

that the malicious websites are spread through smishing. The infection has not spread very
widely at the time of writing, but we’ve seen that many users have already received its SMS
content.

[Page 3]

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.aqyh.xolo` | 域名类型 |
| `com.dhp.ozqh` | 域名类型 |
| `globalanab.tumblr.com` | 域名类型 |
| `hormonaljgrj.tumblr.com` | 域名类型 |
| `jp.co.sagawa.SagawaOfficialApp` | 域名类型 |
| `mainsheetgyam.tumblr.com` | 域名类型 |
| `www.instagram.com` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `332e68d865009d627343b89a5744843e3fde4ae870193f36b82980363439a425` | 恶意文件 |
| `403401aa71df1830d294b78de0e5e867ee3738568369c48ffafe1b15f3145588` | 恶意文件 |
| `466dafa82a4460dcad722d2ad9b8ca332e9a896fc59f06e16ebe981ad3838a6b` | 恶意文件 |
| `5022495104c280286e65184e3164f3f248356d065ad76acef48ee2ce244ffdc8` | 恶意文件 |
| `a0f3df39d20c4eaa410a61a527507dbc6b17c7f974f76e13181e98225bda0511` | 恶意文件 |
| `cb412b9a26c1e51ece7a0e6f98f085e1c27aa0251172bf0a361eb5d1165307f7` | 恶意文件 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `https://globalanab.tumblr.com` | 钓鱼/下载 |
| `https://hormonaljgrj.tumblr.com` | 钓鱼/下载 |
| `https://mainsheetgyam.tumblr.com` | 钓鱼/下载 |
| `https://twitter.com/asdqweqweqeqw` | 钓鱼/下载 |
| `https://twitter.com/fdgoer343` | 钓鱼/下载 |
| `https://twitter.com/gyugyu87418490` | 钓鱼/下载 |
| `https://twitter.com/lucky876543` | 钓鱼/下载 |
| `https://twitter.com/lucky88755` | 钓鱼/下载 |
| `https://twitter.com/lucky98745` | 钓鱼/下载 |
| `https://twitter.com/luckyone1232` | 钓鱼/下载 |
| `https://twitter.com/sadwqewqeqw` | 钓鱼/下载 |
| `https://twitter.com/sdfghuio342` | 钓鱼/下载 |
| `https://twitter.com/ukenivor3` | 钓鱼/下载 |
| `https://www.instagram.com/freedomguidepeople1830` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), SMiShing (短信钓鱼), 钓鱼, 即时通讯软件传播, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到3类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): config_update
2. **勒索软件** (HIGH): 发现
3. **蠕虫传播** (HIGH): 发现
