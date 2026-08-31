# Android banking trojan masquerades - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Android banking trojan masquerades
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 土耳其
| 活动时间 | 未知
| 传播方式 | 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Malware
Android banking trojan masquerades
as Flash Player and bypasses 2FA
This malware masquerades as Flash Player, behaves like a screen locker, and can bypass two-
factor authentication. This combination of features turns it into a powerful tool for stealing
money from victims’ bank accounts.
Lukas Stefanko
09 Mar 2016 • 6 min. read
[Page 2]
Active users of mobile banking apps should be aware of a new Android banking trojan campaign
targeting customers of large banks in Australia, New Zealand and Turkey. The banking malware,
detected by ESET security products as Android/Spy.Agent.

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account, device_info

Android banking trojan masquerades
as Flash Player and bypasses 2FA
This malware masquerades as Flash Player, behaves like a screen locker, and can bypass two-
factor authentication. This combination of features turns it into a powerful tool for stealing
money from victims’ bank accounts.
Lukas Stefanko
09 Mar 2016 • 6 min. read

### 3.2 远程控制 (**CRITICAL**)

266B572B093DB550778BA7824E32D88639B78AFC
E4FA83A479642792BC89CA3C1553883066A19B6C
644644A30DE78DDCD50238B20BF8A70548FF574C
F1AAAE29071CBC23C33B4282F1C425124234481C
CAC078C80AD1FF909CC9970E3CA552A5865C7963
1C8D0E7BB733FBCEB05C40E0CE26288487655738
FE6AC1915F8C215ECEC227DA6FB341520D68A9C7

Additional information
ESET detection name:
Android/Spy.Agent.SI
C&C servers:
http://94.198.97.202
http://46.105.95.130
http://181.174.164.138

Figure 4 - Deactivating administrator rights
The user is then able to uninstall the malware via Settings -> Apps/Application manager -> Flash
Player -> Uninstall.
Removal can become more complicated if the device receives a command from the server to
disable deactivation of device administrator rights. If this happens, when the user tries to
deactivate it, the malware creates an overlay activity in the foreground which prevents the user
from clicking on the confirmation button. Deactivating administrator rights will therefore fail.

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

[Page 1]
Malware
Android banking trojan masquerades
as Flash Player and bypasses 2FA
This malware masquerades as Flash Player, behaves like a screen locker, and can bypass two-
factor authentication. This combination of features turns it into a powerful tool for stealing

[Page 1]
Malware
Android banking trojan masquerades
as Flash Player and bypasses 2FA
This malware masquerades as Flash Player, behaves like a screen locker, and can bypass two-
factor authentication. This combination of features turns it into a powerful tool for stealing

### 3.4 C2 反检测 (**HIGH**)

sending them to a remote server, at which point the malicious overlay closes. The malware does
not focus only on mobile banking apps, but also tries to obtain Google account credentials as well.
The first versions were simple, with an easily identifiable malicious purpose. Later versions featured
better obfuscation and encryption.
Process summary
If a target application is launched, the malware is triggered and a fake login screen overlays the

### 3.6 广告欺诈 (**MEDIUM**)

Removal can become more complicated if the device receives a command from the server to
disable deactivation of device administrator rights. If this happens, when the user tries to
deactivate it, the malware creates an overlay activity in the foreground which prevents the user
from clicking on the confirmation button. Deactivating administrator rights will therefore fail.

[Page 7]
Figure 5 - Overlay screen displayed by the malware

### 3.7 蠕虫传播 (**HIGH**)

com.paypal.android.p2pmobile
com.ebay.mobile
com.skype.raider
com.whatsapp
com.google.android.googlequicksearchbox

[Page 15]

detected by ESET security products as Android/Spy.Agent.SI, can steal login credentials from 20
mobile banking apps.The list of target banks includes the largest banks in each of the three target
countries (A full list can be found in the final section of this article ). Thanks to its ability to intercept
SMS communications, the malware is also able to bypass SMS-based two-factor authentication.
Analysis
The malware masquerades as Flash Player, with a legitimate-looking icon.
It was available on several servers. These servers were registered in late January and February 2016.

### 3.8 权限滥用 (**HIGH**)

package names of installed applications (including mobile banking apps) and sends them to the
remote server. If any of the installed apps are targets of the malware, the server sends a full list of
49 target apps, although not all of these are directly attacked.
The malware manifests itself as an overlay, appearing over the launched banking application: this
phishing activity behaves like a lock screen, which can’t be terminated without the user entering
their login credentials. The malware does not verify the credibility of the data entered, instead
sending them to a remote server, at which point the malicious overlay closes. The malware does

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `181.174.164.138` | 域名类型 |
| `46.105.95.130` | 域名类型 |
| `94.198.97.202` | 域名类型 |
| `au.com.bankwest.mobile` | 域名类型 |
| `au.com.mebank.banking` | 域名类型 |
| `au.com.nab.mobile` | 域名类型 |
| `au.com.westpac.onlineinvesting` | 域名类型 |
| `biz.mobinex.android.apps.cep_sifrematik` | 域名类型 |
| `com.akbank.android.apps.akbank_direkt` | 域名类型 |
| `com.android.chrome` | 域名类型 |
| `com.android.vending` | 域名类型 |
| `com.anz.android.gomoney` | 域名类型 |
| `com.bendigobank.mobile` | 域名类型 |
| `com.commbank.netbank` | 域名类型 |
| `com.ebay.mobile` | 域名类型 |
| `com.finansbank.mobile.cepsube` | 域名类型 |
| `com.garanti.cepsubesi` | 域名类型 |
| `com.google.android.apps.books` | 域名类型 |
| `com.google.android.apps.docs` | 域名类型 |
| `com.google.android.apps.docs.editors.docs` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `181.174.164.138` | 服务器 |
| `46.105.95.130` | 服务器 |
| `94.198.97.202` | 服务器 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `http://adobeflashplaayer.com/download` | 钓鱼/下载 |
| `http://adobeplayerdownload.com/download` | 钓鱼/下载 |
| `http://adobeupdateflash11.com/download` | 钓鱼/下载 |
| `http://adobeupdateplayeer.com/download` | 钓鱼/下载 |
| `http://adobeupdateplayer.com/download` | 钓鱼/下载 |
| `http://adobeuploadplayer.com/download` | 钓鱼/下载 |
| `http://flashplayeerupdate.com/download` | 钓鱼/下载 |

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
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
