# By: Tony Bao - 分析报告

> **来源**: Trend Micro
> **发布日期**: Dec 19, 2018
> **作者**: Tony Bao
Dec
> **恶意软件名称**: By: Tony Bao
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等)
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Mobile
Android Wallpaper Apps Found Running Ad Fraud Scheme
Analyzed 15 malicious wallpaper apps we found on Google Play Store running click ad fraud schemes. The apps recorded over 200,000 downloads worldwide before they were
removed.
By: Tony Bao
Dec 19, 2018
Read time: 2 min (656 words)
We detected 15 wallpaper apps in Google Play Store committing click ad fraud. The said apps
were collectively downloaded from Play Store more than 222,200 times at the time of writing,
and our telemetry showed Italy, Taiwan, the United States, Germany and Indonesia with the
most infections recorded.

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

Safari/537.36&cb=5c1236f316e45
Trend Micro Solutions
Users have to be vigilant and be cautious of the apps they download, as cybercriminals will
continue manipulating app features to profit, steal information and attack. Mobile devices have
to be protected with a comprehensive security structure and program against mobile malware.
Trend Micro Mobile Security detects this threat and defends devices from all related threats. It
blocks malicious apps , and end users can also benefit from its multilayered security capabilities

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

com.amz.wildcats 0995b52a9a12cf31ae19c360d56ca1a20d784eecc9b018514dbf01446f4ad36e 10,000+
com.amz.underwaterworld 1f6907b2e8f7fa7597a28b2e7133325fcddb3e4f9e1c3cbad82afaa82bf3c57e 5,000+
com.appmakerz.dclock b098d0ee0766558dff37761358d250a7b648c1de1556bd0345564b74a6db848c 50,000+
com.appmakerz.shark fbcc2c9ddc69c0f272f80051987b5ed911cd112ef6e26709b54e67cae7ce1fb6 50,000+
com.appmakerz.xphone aec79ed8cb779474a058e89bd4f1a55a534d439af5d48751867300a885d50182 10,000+
com.appmakerz.dolphins 48d7ebf7fd65cb317e52c5d331d193bfaf3f48590b8f598292be88f26dc8464e 10,000+
com.appmakerz.ocean 034aa9f3ceeb74acf38c0f4036bb0e89339759ed73de009207c7036eb25e14a5 10,000+

app was rated 4.8 on Google Play Store.

[Page 4]
Once downloaded, the apps decode the command and control (C&C) server address for the
configuration.
Figure 3. C&C server address decoded and run.
The entire process is muted to hide the activity from the user. An HTTP GET request is

app was rated 4.8 on Google Play Store.

[Page 4]
Once downloaded, the apps decode the command and control (C&C) server address for the
configuration.
Figure 3. C&C server address decoded and run.
The entire process is muted to hide the activity from the user. An HTTP GET request is

app was rated 4.8 on Google Play Store.

[Page 4]
Once downloaded, the apps decode the command and control (C&C) server address for the
configuration.
Figure 3. C&C server address decoded and run.
The entire process is muted to hide the activity from the user. An HTTP GET request is

### 3.5 勒索软件 (**HIGH**)

to be protected with a comprehensive security structure and program against mobile malware.
Trend Micro Mobile Security detects this threat and defends devices from all related threats. It
blocks malicious apps , and end users can also benefit from its multilayered security capabilities
that secure the device’s data and privacy, and safeguard them from ransomware, fraudulent
websites, and identity theft.

For organizations, Trend Micro™ Mobile Security for Enterprise provides device, compliance and

### 3.6 广告欺诈 (**MEDIUM**)

[Page 1]
Mobile
Android Wallpaper Apps Found Running Ad Fraud Scheme
Analyzed 15 malicious wallpaper apps we found on Google Play Store running click ad fraud schemes. The apps recorded over 200,000 downloads worldwide before they were
removed.
By: Tony Bao

[Page 1]
Mobile
Android Wallpaper Apps Found Running Ad Fraud Scheme
Analyzed 15 malicious wallpaper apps we found on Google Play Store running click ad fraud schemes. The apps recorded over 200,000 downloads worldwide before they were
removed.
By: Tony Bao
Dec 19, 2018

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `0.2743.100` | 域名类型 |
| `1.125.77` | 域名类型 |
| `203.90.248.163` | 域名类型 |
| `com.amz.skull` | 域名类型 |
| `com.amz.underwaterworld` | 域名类型 |
| `com.amz.wildcats` | 域名类型 |
| `com.appmakerz.crackedscreen` | 域名类型 |
| `com.appmakerz.dclock` | 域名类型 |
| `com.appmakerz.dolphins` | 域名类型 |
| `com.appmakerz.koi` | 域名类型 |
| `com.appmakerz.ocean` | 域名类型 |
| `com.appmakerz.shark` | 域名类型 |
| `com.appmakerz.waterdrop` | 域名类型 |
| `com.appmakerz.xphone` | 域名类型 |
| `com.mobixa.christmas` | 域名类型 |
| `com.mobixa.curvededges` | 域名类型 |
| `com.mobixa.starrysky` | 域名类型 |
| `com.mobixa.sunset` | 域名类型 |
| `pub.mobday.com` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `198.1.125.77` | 服务器 |
| `203.90.248.163` | 服务器 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `034aa9f3ceeb74acf38c0f4036bb0e89339759ed73de009207c7036eb25e14a5` | 恶意文件 |
| `0995b52a9a12cf31ae19c360d56ca1a20d784eecc9b018514dbf01446f4ad36e` | 恶意文件 |
| `1f6907b2e8f7fa7597a28b2e7133325fcddb3e4f9e1c3cbad82afaa82bf3c57e` | 恶意文件 |
| `48d7ebf7fd65cb317e52c5d331d193bfaf3f48590b8f598292be88f26dc8464e` | 恶意文件 |
| `8d643500319bd9e4eb2007ac43613bf53943b65dff25ee933d5450ecc11402b8` | 恶意文件 |
| `8f16246b9afc1dfb89ca8b60f1b097584b94034e0de6496bbc28e58d667c4af5` | 恶意文件 |
| `a2ef230d3b091c0571bb0c96b456c17f94a176a2861281b6ff0b56e789e17b64` | 恶意文件 |
| `aec79ed8cb779474a058e89bd4f1a55a534d439af5d48751867300a885d50182` | 恶意文件 |
| `b098d0ee0766558dff37761358d250a7b648c1de1556bd0345564b74a6db848c` | 恶意文件 |
| `bc8237bf6a9b25e71bb55c0841c1ee6ef443835bf172666a680f74badadf34f8` | 恶意文件 |
| `bf016cf1142b17c5a088a80feb88fb10ab9be05c20133931b7190e352a1f1b08` | 恶意文件 |
| `d34598835b28a6ad070dd0986b0bbc336c8ba7cac9a9a22d6b3c6a99049242a6` | 恶意文件 |
| `ee6ef277ea9d8478965452e10c0c01cd7a4d13c1cd23e9ee8d2668a715f7a6b5` | 恶意文件 |
| `fa8f9d3415bc38b679204f2c8fd983e12298e014007f2a18f7501e3c1d3d1910` | 恶意文件 |
| `fbcc2c9ddc69c0f272f80051987b5ed911cd112ef6e26709b54e67cae7ce1fb6` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等) |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): 发现
2. **远程控制** (CRITICAL): config_update
3. **勒索软件** (HIGH): 发现
4. **广告欺诈** (MEDIUM): 发现
