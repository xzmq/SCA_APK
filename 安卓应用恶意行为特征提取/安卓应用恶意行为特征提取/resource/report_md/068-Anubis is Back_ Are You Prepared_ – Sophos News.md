# [Page 1] - 分析报告

> **来源**: Sophos
> **发布日期**: 未知
> **作者**: to fool the Play Store defense
> **恶意软件名称**: [Page 1]
> **厂商检测名**: `Sophos detects Anubis`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
PRODUCTS SOLUTIONS PARTNERS SUPPORT
Overview Press Events Community Blog Careers Contact
Search
Anubis is Back: Are
You Prepared?
SophosLabs Uncut • Android Banker • Anubis • Banking malware • You might also
enjoy...
Sophos Mobile
This fully-featured bot is, once again, managing to
21
bypass Google Play Store security measures. We
OCT
look at just how dangerous the Anubis mobile
malware can be.
14 AUGUST 2018
CORPORATE • MALWAR…
Fake Android
banking apps
target victims
in India
By Jagadeesh Chandraiah
By Jagadeesh Chandraiah
[Page 2]
Known to Android researchers as credential-stealing

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

By Jagadeesh Chandraiah

[Page 2]
Known to Android researchers as credential-stealing
malware that (predominantly) targets Turkish users,
a malware family called Anubis has successfully
infiltrated the Google Play Store in the past few

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

[Page 4]
Once installed, the downloader will collect device
data, send a beacon signal to the C2 server, and also
download more applications.
In the following code, you can see the references to
the CnC server and the configuration data of the

[Page 3]
These apps are downloaders: they fetch the payload
after successful installation and interaction with
command and control server.
With millions of applications on the Play Store that
download some kind of content from the Internet,
it’s difficult for Google Play’s security service to scan

in reality, it functions as a downloader. Once
activated, the Anubis app fetches the main
malicious payload, which is designed to steal
banking credentials and provide remote control
functionality of the compromised device to the
botnet owners.
Google swept clean the Play Store after Anubis was

[Page 4]
Once installed, the downloader will collect device
data, send a beacon signal to the C2 server, and also
download more applications.
In the following code, you can see the references to
the CnC server and the configuration data of the

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing

Search
Anubis is Back: Are
You Prepared?
SophosLabs Uncut • Android Banker • Anubis • Banking malware • You might also
enjoy...
Sophos Mobile
This fully-featured bot is, once again, managing to

Search
Anubis is Back: Are
You Prepared?
SophosLabs Uncut • Android Banker • Anubis • Banking malware • You might also
enjoy...
Sophos Mobile
This fully-featured bot is, once again, managing to

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

}
catch(Throwable v1) {
this.e.c.a("SOUND", "STOP RECORD SOUND");
The built-in ransomware component encrypts user
files and gives them .Anubiscrypt file extension.

[Page 7]

### 3.5 勒索软件 (**HIGH**)

capturing screen contents
location tracking
keylogging
Ransomware
Here’s a snippet of code from the sound recorder
function:
MediaRecorder v6 = new MediaRecorder();

### 3.6 广告欺诈 (**MEDIUM**)

Accessibility permission request access, pretending
to be a Google Protect request.
Accessibility permission provides malware with
additional ability to simulate clicks for buttons
displayed on the screen, get callbacks for certain
events and construct the context of the device to
steal users data.

### 3.7 蠕虫传播 (**HIGH**)

Explains alot inspite of the two virus
scanners and five anti malware
programs I have an anubis that is
spreading on my tablet. First it is I
can’t use google, then it is yahoo
then lumosity. I have shut everything
off until I can find a way to get rid of

they download and activate their malicious content.
This simple but extremely vicious trick allows
malware authors to fool the Play Store defense
mechanisms. We’ve seen malware authors use this
delaying tactic before and, based on the success we
see, will likely continue to do so in the future — at
least until Google introduces some kind of

### 3.8 权限滥用 (**HIGH**)

As previously mentioned, the dropped payload is the
Anubis banking trojan itself.
Once executed, the malicious payload pops up an
Accessibility permission request access, pretending
to be a Google Protect request.
Accessibility permission provides malware with
additional ability to simulate clicks for buttons

Config.SERVER_TRY_COUNT = 5;
}
The data collected by the malware includes such
parameters as IMEI, OS version, model name, root
status:
((Map)v3).put(Rows.api_req, "1");
((Map)v3).put(Rows.api_imei, Utils.getImei(arg6));

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

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
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): config_update
3. **银行木马** (CRITICAL): phishing
4. **C2 反检测** (HIGH): twitter
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
