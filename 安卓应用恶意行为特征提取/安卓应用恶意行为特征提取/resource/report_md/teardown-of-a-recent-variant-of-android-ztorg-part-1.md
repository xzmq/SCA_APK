# Locating the Malicious Code - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Locating the Malicious Code
> **厂商检测名**: `detect
ro.product`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
FFOORRTTIIGGUUAARRDD LLAABBSS TTHHRREEAATT RREESSEEAARRCCHH
TTeeaarrddoowwnn ooff aa RReecceenntt VVaarriiaanntt ooff AAnnddrrooiidd//ZZttoorrgg ((PPaarrtt 11))
By Axelle Apvrille| March 15, 2017
Ztorg, also known as Qysly, is one of those big families of Android malware. It first appeared in April 2015, and now has over 25 variants, some of
which are still active in 2017. Yet, there aren't many technical descriptions for it - except for the initial Ztorg.A sample - so I decided to have a look at
one of the newer variants, Android/Ztorg.AM!tr, that we detected on January 20, 2017.
The

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

/dev/socket/baseband_genyd presence of file
/dev/socket/qemud presence of file
/dev/qemu_pipe presence of file
/data/app/com.bluestacks.BstCommandProcessor-1.apk presence of file
/data/app/com.bluestacks.help-1.apk presence of file
/data/app/com.bluestacks.home-1.apk presence of file
/data/app/com.bluestacks.s2p-1.apk presence of file

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: app_replace

Sitemap
Blog Sitemap
Copyright © 2026 Fortinet, Inc. All Rights Reserved Terms of Services Privacy Policy | Cookie Settings
Also of Interest: VPNFilter Malware - Critical Update Android Malware Masquerades as Banking App, Part II
Locker: an Android ransomware full of surprises Teardown of Android/Ztorg (Part 2)

Sitemap
Blog Sitemap
Copyright © 2026 Fortinet, Inc. All Rights Reserved Terms of Services Privacy Policy | Cookie Settings
Also of Interest: VPNFilter Malware - Critical Update Android Malware Masquerades as Banking App, Part II
Locker: an Android ransomware full of surprises Teardown of Android/Ztorg (Part 2)

com.batmobi: Batmobi for mobile advertising
com.catchgift: code shows this is clearly for advertising
com.marswin89: this is a MarsDaemon, a library to keep apps alive. Interesting, but not malicious as such.
com.squareup: well-known mobile payment
com.umeng: well-known mobile advertising & analytics
So, where is the malicious code? Or is it just some not-so-clean code in one of these SDKs that triggered a (false positive) alert?
I kept on looking in other namespaces of the app:

### 3.4 C2 反检测 (**HIGH**)

malicious stuff? At this point, we aren't convinced yet that this is not a False Positive.
Actually, we're getting closer. After the sample has tested it is not running on an emulator, it sends an HTTP
request to hXXp://bbs.tihalf.com/only/[$1]/2.html?. This is a URL we de-obfuscated at the previous step. The [$1] is replaced with gp1187 (another
de-obfuscated string), and an information blob is appended to the url, where the blob is a DES-encrypted JSON object containing code version,
SDK version, etc.
This is getting more suspicious.
The response is base64 encoded, and encrypted with DES-CBC (see class a.c.a):

### 3.5 勒索软件 (**HIGH**)

Threat Research
FortiGuard Labs
Threat Map
Ransomware Prevention
Connect With Us
Fortinet Community
Partner Portal

### 3.6 广告欺诈 (**MEDIUM**)

com.umeng: well-known mobile advertising & analytics
So, where is the malicious code? Or is it just some not-so-clean code in one of these SDKs that triggered a (false positive) alert?
I kept on looking in other namespaces of the app:
u.aly contained code for Mobclick - advertising again (hey, for the sake of AV analysts at least, can you developers stop using so many
advertising SDKs, huh?),
android.support.v4 is standard for app development.
Namespace e.i.o.q isn't doing anything apart calling functions from the a namespace.

### 3.8 权限滥用 (**HIGH**)

THREAT RESEARCH
Teardown of Android/Ztorg (Part 2)
THREAT RESEARCH
Unmasking Android Malware: A Deep Dive into a New Rootnik Variant, Part I

[Page 18]
THREAT RESEARCH

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `alla.tihalf.com` | 域名类型 |
| `android.support.v4` | 域名类型 |
| `audio.primary.vbox86.so` | 域名类型 |
| `bbs.tihalf.com` | 域名类型 |
| `camera.vbox86.so` | 域名类型 |
| `com.androVM.vmconfig` | 域名类型 |
| `com.bluestacks.BstCommandProcessor` | 域名类型 |
| `com.bluestacks.accelerometerui` | 域名类型 |
| `com.bluestacks.appfinder` | 域名类型 |
| `com.bluestacks.appmart` | 域名类型 |
| `com.bluestacks.appmart.cfgpresence` | 域名类型 |
| `com.bluestacks.appsettings` | 域名类型 |
| `com.bluestacks.help` | 域名类型 |
| `com.bluestacks.home` | 域名类型 |
| `com.bluestacks.s2p` | 域名类型 |
| `com.bluestacks.searchapp` | 域名类型 |
| `com.bluestacks.settings` | 域名类型 |
| `com.bluestacks.setup` | 域名类型 |
| `com.bluestacks.spotlight` | 域名类型 |
| `com.mx.cool.videoplayer.activity.MainActivity` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `2c546ad7f102f2f345f30f556b8d8162bd365a7f1a52967fce906d46a2b0dac4` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到6类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): config_update
2. **银行木马** (CRITICAL): app_replace
3. **C2 反检测** (HIGH): 发现
4. **勒索软件** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
7. 其他行为见详细信息...
