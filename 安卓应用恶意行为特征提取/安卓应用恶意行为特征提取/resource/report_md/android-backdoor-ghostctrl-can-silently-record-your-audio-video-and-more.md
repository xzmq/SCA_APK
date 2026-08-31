# Cyber Threats - 分析报告

> **来源**: Trend Micro
> **发布日期**: Jul 17, 2017
> **作者**: Lenart Bermejo
> **恶意软件名称**: Cyber Threats
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 蓝牙/U盘传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

attack chain of GhostCtrl’s third version
In GhostCtrl’s third version, the wrapper APK first drops a packed APK. The latter unpacks the
main APK, a Dalvik executable (DEX), and an Executable and Linkable Format file (ELF). The DEX
and ELF files decrypt strings and Application Programming Interface (API) calls in the main
malicious APK in runtime. This longwinded attack chain helps make detection more challenging,
exacerbated by the fact that the wrapper APK hides the packed APK as well as DEX and ELF files
in the assets directory.

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account, clipboard

Read time: 6 min (1668 words)

Updated as of August 6, 2017, 7:45 PM PDT to clarify GhostCtrl's attack vectors.
The information-stealing RETADUP worm that affected Israeli hospitals is actually just part of an
attack that turned out to be bigger than we first thought—at least in terms of impact. It was
accompanied by an even more dangerous threat: an Android malware that can take over the
device.

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

Detected by Trend Micro as ANDROIDOS_GHOSTCTRL.OPS / ANDROIDOS_GHOSTCTRL.OPSA,
we’ve named this Android backdoor GhostCtrl as it can stealthily control many of the infected
device’s functionalities. 
GhostCtrl was hosted in RETADUP's C&C infrastructure, and the samples we analyzed
masqueraded as a legitimate or popular app that uses the names App, MMS, whatsapp, and

[Page 2]

into thinking it’s a legitimate system application. The malicious APK will then connect to the C&C

[Page 4]
server to retrieve commands via the socket (an endpoint for communication between machines),
new Socket("hef--klife[.]ddns.net", 3176).
GhostCtrl can possess the infected device to do its bidding
The commands from the C&C server are encrypted and locally decrypted by the APK upon

accompanied by an even more dangerous threat: an Android malware that can take over the
device.
Detected by Trend Micro as ANDROIDOS_GHOSTCTRL.OPS / ANDROIDOS_GHOSTCTRL.OPSA,
we’ve named this Android backdoor GhostCtrl as it can stealthily control many of the infected
device’s functionalities. 
GhostCtrl was hosted in RETADUP's C&C infrastructure, and the samples we analyzed
masqueraded as a legitimate or popular app that uses the names App, MMS, whatsapp, and

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: forum, domain_gen

server to retrieve commands via the socket (an endpoint for communication between machines),
new Socket("hef--klife[.]ddns.net", 3176).
GhostCtrl can possess the infected device to do its bidding
The commands from the C&C server are encrypted and locally decrypted by the APK upon
receipt. Interestingly, we also found that the backdoor connects to a domain rather than directly
connecting to the C&C server’s IP address. This can be an attempt to obscure their traffic. We
also found several Dynamic Name Servers (DNS), which at some point led to the same C&C IP

### 3.5 勒索软件 (**HIGH**)

Figure 7: Code snapshot of GhostCtrl’s second version applying device admin privileges

[Page 10]
GhostCtrl’s second version can also be a mobile ransomware. It can lock the device’s screen and
reset its password, and also root the infected device. It can also hijack the camera, create a
scheduled task of taking pictures or recording video, then surreptitiously upload them to the
C&C server as mp4 files.

### 3.6 广告欺诈 (**MEDIUM**)

GhostCtrl is hauntingly persistent
When the app is launched, it base64-decodes a string from the resource file and writes it down,
which is actually the malicious Android Application Package (APK).
The malicious APK, after dynamically clicked by a wrapper APK, will ask the user to install it.
Avoiding it is very tricky: even if the user cancels the “ask for install page” prompt, the message
will still pop up immediately. The malicious APK doesn’t have an icon. Once installed, a wrapper
APK will launch a service that would let the main, malicious APK run in the background:

### 3.7 蠕虫传播 (**HIGH**)

[Page 1]
Cyber Threats
Android Backdoor GhostCtrl Records Your Audio, Video
The RETADUP worm that affected Israeli hospitals turned out have bigger impact than we first thought. It was accompanied by an even more dangerous threat: an Android malware
that can take over the device. We’ve named this Android backdoor GhostCtrl.
By: Lenart Bermejo, Jordan Pan, Cedric Pernet
Jul 17, 2017

we’ve named this Android backdoor GhostCtrl as it can stealthily control many of the infected
device’s functionalities. 
GhostCtrl was hosted in RETADUP's C&C infrastructure, and the samples we analyzed
masqueraded as a legitimate or popular app that uses the names App, MMS, whatsapp, and

[Page 2]
even Pokemon GO. Socially engineered phishing emails were also attack vectors; they had

ACTION CODE= 60: Use the text to speech feature (translate text to voice/audio)

ACTION CODE= 62: Send SMS/MMS to a number specified by the attacker; the content can also be customized

ACTION CODE= 68: Delete browser history

### 3.8 权限滥用 (**HIGH**)

Control the Bluetooth to search and connect to another device

Set the accessibility to TRUE and terminate an ongoing phone call

How do GhostCtrl’s versions stack up to each other?
GhostCtrl’s first version has a framework that enables it to gain admin-level privilege. While it had

[Page 10]
GhostCtrl’s second version can also be a mobile ransomware. It can lock the device’s screen and
reset its password, and also root the infected device. It can also hijack the camera, create a
scheduled task of taking pictures or recording video, then surreptitiously upload them to the
C&C server as mp4 files.
Figure 8: Code snapshot showing GhostCtrl’s ransomware-like capability

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.android.engine` | 域名类型 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 蓝牙/U盘传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): forum, domain_gen
4. **勒索软件** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
