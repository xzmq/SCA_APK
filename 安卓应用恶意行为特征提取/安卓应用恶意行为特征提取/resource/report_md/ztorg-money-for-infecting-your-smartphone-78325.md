# MALWARE DESCRIPTIONS 15 MAY 2017 13 minute read - 分析报告

> **来源**: 未知
> **发布日期**: May 16, 2017
> **作者**: ROMAN UNUCHEK
> **恶意软件名称**: MALWARE DESCRIPTIONS 15 MAY 2017 13 minute read
> **厂商检测名**: `iappzone.net`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 俄罗斯, 越南
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Ztorg: money for infecting your smartphone
MALWARE DESCRIPTIONS 15 MAY 2017 13 minute read
// AUTHORS
ROMAN UNUCHEK
This research started when we discovered an infected Pokémon GO guide in Google Play. It was
there for several weeks and was downloaded more than 500,000 times. We detected the malware
as Trojan.AndroidOS.Ztorg.ad. After some searching, I found some other similar infected apps that
were being distributed from the Google Play Store. The first of them, called Privacy Lock, was
uploaded to Google Play on 15 December 2016. It was one of the most popular Ztorg modifications,

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: contacts, account

[Page 19]
Mobile malware evolution
2017
Still Stealing
Payload (main module)
In all the attacks that I analyzed the main module had the same functionality. I’ll describe one of the
most recent – 2dac26e83b8be84b4a453664f68173dd. It was downloaded by the

### 3.2 远程控制 (**CRITICAL**)

Still Stealing
Payload (main module)
In all the attacks that I analyzed the main module had the same functionality. I’ll describe one of the
most recent – 2dac26e83b8be84b4a453664f68173dd. It was downloaded by the
com.unit.conversion.use app using the malicious MyGame library.
This module is downloaded by the infection module and loaded using the ClassLoad method. The
main purpose of the module is to gain root rights and install other modules. It does this by

dozen values for different system properties. If this check is passed, the Trojan will start a new
thread.
In this new thread the Trojan will wait a random amount of time, between an hour and an hour and a
half. After waiting it will make a GET HTTP request to the C&C (em.kmnsof.com/only) and, as a
result, the Trojan will receive a JSON file encrypted with DES. This JSON should contain a URL from
which a file can be downloaded. The file is an ‘xorred’ JAR that contains the malicious classes.dex –
the main module.

[Page 17]
flag. If both of these methods return “false”, the malicious library will execute a GET request to the
command server.
It receives:
“BEgHSARIB0oESg4SEhZcSUkCCRFICAUSHwoLEhZIBQkLSQ4fSQ4fVlZVSQEWVlZVSAcWDUpe
Vg==”

framework used by
CloudComputating group in
cyberespionage campaigns
It used the same command and control servers as .gmtgp.apk.
Conclusion
During the research period I found that Trojan.AndroidOS.Ztorg was uploaded to Google Play Store
almost 100 times as different apps. The first of them was called Privacy Lock, had more than 1

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: app_replace, phishing

distribution channels
DownloadProvider
All of these folders were used by some of the malware to spread the initial Ztorg infection and were
used after infection to distribute other apps – some of them malicious. Download a banker to track
your parcel
Other Trojans
AnalysisofElpaco:aMimic

### 3.4 C2 反检测 (**HIGH**)

thread.
In this new thread the Trojan will wait a random amount of time, between an hour and an hour and a
half. After waiting it will make a GET HTTP request to the C&C (em.kmnsof.com/only) and, as a
result, the Trojan will receive a JSON file encrypted with DES. This JSON should contain a URL from
which a file can be downloaded. The file is an ‘xorred’ JAR that contains the malicious classes.dex –
the main module.
Native

### 3.5 勒索软件 (**HIGH**)

One of them, called Money Converter (com.countrys.converter.currency,
Ymir: new stealthy
55366B684CE62AB7954C74269868CD91), had been installed more than 10,000 times from Google
ransomware in the wild
Play. Its purpose is similar to that of the .gmtgp.apk module – it uses Accessibility Services to install
apps from Google Play. Therefore, the Trojan can silently install and run promoted apps without any
interaction with the user, even on updated devices where it cannot gain root rights. QSC: A multi-plugin

### 3.6 广告欺诈 (**MEDIUM**)

[sdcard]/DownloadProvider/download/ SANTIAGO PONTIROLI
I analyzed the apps using these paths and discovered that all of them are already detected by
22 JUL 2020, 2:00PM
Kaspersky Lab products as adware or malware. However, the apps downloaded to these folders are GReAT Ideas. Powered by SAS: threat
not all malicious – most of them are clean. hunting and new techniques
DMITRY BESTUZHEV,COSTIN RAIU,PIERRE DELCHER,
BRIAN BARTHOLOMEW,BORIS LARIN,ARIEL JUNGHEIT,

By analyzing these URLs we can identify infected apps on Google Play.
Malicious server
URLs from iappzone.net look like this:
http://track.iappzone.net/click/click?
offer_id=3479&aff_id=3475&campaign=115523_201|1002009&install_callback=http://track.superson
icads.com/api/v1/processCommissionsCallback.php?
advertiserId=85671&password=540bafdb&dynamicParameter=dp5601581629793224906

### 3.7 蠕虫传播 (**HIGH**)

The Trojan uses accessibility services to install (or even buy) apps from the Google Play Store.
It also downloads apps into the .googleplay_download directory on the SD card and installs them
using accessibility services to click buttons. The folder .googleplay_download is one of the sources
used to spread the Ztorg Trojan. It can click buttons that use one of 13 languages – English,

[Page 23]
Spanish, Arabic, Hindi, Indonesian, French, Persian, Russian, Portuguese, Thai, Vietnamese, Turkish

### 3.8 权限滥用 (**HIGH**)

case it downloads Trojan-Clicker.AndroidOS.Gopl.a (af9a75232c83e251dd6ef9cb32c7e2ca).
 
Its C&C is http://g.ieuik.com/pilot/api/; additional domains are g.uikal.com and api.ddongfg.com.
The Trojan uses accessibility services to install (or even buy) apps from the Google Play Store.
It also downloads apps into the .googleplay_download directory on the SD card and installs them
using accessibility services to click buttons. The folder .googleplay_download is one of the sources
used to spread the Ztorg Trojan. It can click buttons that use one of 13 languages – English,

Comments
To be honest, I was surprised that only one was malicious – all the other apps were clean.
Advertising
The funny thing is that they check for root rights on the device and don’t pay those that have
them. And the first thing that Ztorg did on the device after infection started was to get superuser Apps that pay users
rights.
Campaigns

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `139.162.57.41` | 域名类型 |
| `52.74.22.232` | 域名类型 |
| `52.74.240.149` | 域名类型 |
| `a.apaol.com` | 域名类型 |
| `a.gqkao.com` | 域名类型 |
| `active.agoall.com` | 域名类型 |
| `api.agoall.com` | 域名类型 |
| `api.ddongfg.com` | 域名类型 |
| `api.jigoolng.com` | 域名类型 |
| `api2.batmobil.net` | 域名类型 |
| `app.adjust.com` | 域名类型 |
| `c.oddkc.com` | 域名类型 |
| `click.apprevolve.com` | 域名类型 |
| `co.uhi.tadsafa` | 域名类型 |
| `com.amusing.notes.done` | 域名类型 |
| `com.android.vending` | 域名类型 |
| `com.booster.ram.app.master.clean` | 域名类型 |
| `com.countrys.converter.currency` | 域名类型 |
| `com.ele.wall.papers` | 域名类型 |
| `com.equalizer.goods.listener` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `139.162.57.41` | 服务器 |
| `52.74.22.232` | 服务器 |
| `52.74.240.149` | 服务器 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `http://api.ddongfg.com/pilot/api` | 钓鱼/下载 |
| `http://dow.nctylmtp.com/hy/hy003/gp003.apk` | 钓鱼/下载 |
| `http://dow.nctylmtp.com/hy/hy003/gp003.apk,80` | 钓鱼/下载 |
| `http://g.ieuik.com/pilot/api/;` | 钓鱼/下载 |
| `http://track.iappzone.net/click/click?` | 钓鱼/下载 |
| `http://track.iappzone.net…` | 钓鱼/下载 |
| `https://app.adjust.com/4f1lza?redirect=https://play.google.com/store/apps/details?` | 钓鱼/下载 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @gmail | C2/通信 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): contacts, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): app_replace, phishing
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
