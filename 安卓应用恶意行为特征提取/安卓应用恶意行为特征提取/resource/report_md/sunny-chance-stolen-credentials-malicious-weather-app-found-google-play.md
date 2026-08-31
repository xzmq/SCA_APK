# Sunny with a chance of stolen - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Sunny with a chance of stolen
> **厂商检测名**: `goodish.weather`

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
ESET Research
Sunny with a chance of stolen
credentials: Malicious weather app
found on Google Play
ESET has spotted a new banking malware on Google Play. Disguised as a weather forecast
app, it steals banking credentials and locks screens.
Lukas Stefanko
22 Feb 2017 • 4 min. read
[Page 2]
Android users were the target of new banking malware with screen locking capabilities, which was
disguised as a weather forecast app on Google Play.
Detected by ESET as Trojan.Android/Spy.Banker.HU, the malware was a trojanized version of the
otherwise benign weather forecast application Good Weathe

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account, device_info

credentials: Malicious weather app
found on Google Play
ESET has spotted a new banking malware on Google Play. Disguised as a weather forecast
app, it steals banking credentials and locks screens.
Lukas Stefanko
22 Feb 2017 • 4 min. read

Besides the weather forecast functionalities it adopted from the original legitimate application, the
trojan is able to lock and unlock infected devices remotely and intercept text messages. Apart from
doing so, the trojan targeted the users of 22 Turkish mobile banking apps, whose credentials were
harvested using phony login forms.
Figure 1: Trojanized Good Weather app on Google Play

[Page 3]

### 3.2 远程控制 (**CRITICAL**)

trojan is now all set to start its malicious activity.
Users who are not alarmed at this point might be pleased with the new weather widget they can
add to their home screens. However, in the background, the malware is getting to work sharing
device information with its C&C server.
Depending on the command it gets in return, it can intercept received text messages and send
them to the server, remotely lock and unlock the device by setting a lock screen password of the
attackers’ choice, and harvest banking credentials.

Users who are not alarmed at this point might be pleased with the new weather widget they can
add to their home screens. However, in the background, the malware is getting to work sharing
device information with its C&C server.
Depending on the command it gets in return, it can intercept received text messages and send
them to the server, remotely lock and unlock the device by setting a lock screen password of the
attackers’ choice, and harvest banking credentials.
The trojan displays a fake login screen once the user runs one of the targeted banking apps and

### 3.3 银行木马 (**CRITICAL**)

Sunny with a chance of stolen
credentials: Malicious weather app
found on Google Play
ESET has spotted a new banking malware on Google Play. Disguised as a weather forecast
app, it steals banking credentials and locks screens.
Lukas Stefanko
22 Feb 2017 • 4 min. read

Sunny with a chance of stolen
credentials: Malicious weather app
found on Google Play
ESET has spotted a new banking malware on Google Play. Disguised as a weather forecast
app, it steals banking credentials and locks screens.
Lukas Stefanko
22 Feb 2017 • 4 min. read

### 3.6 广告欺诈 (**MEDIUM**)

com.ziraat.ziraatmobil
com.intertech.mobilemoneytransfer.activity
com.kuveytturk.mobil
com.magiclick.odeabank
Let us keep you up to date
Sign up for our newsletters
Your Email Address

### 3.7 蠕虫传播 (**HIGH**)

disguised as a weather forecast app on Google Play.
Detected by ESET as Trojan.Android/Spy.Banker.HU, the malware was a trojanized version of the
otherwise benign weather forecast application Good Weather.
The malicious app managed to get around Google’s security mechanisms and appeared in the store
on February 4th, only to be reported by ESET two days later and consequently pulled from the
store. During its short lifetime, the app found its way to devices of up to 5000 users.
Besides the weather forecast functionalities it adopted from the original legitimate application, the

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `biz.mobinex.android.apps.cep_sifrematik` | 域名类型 |
| `com.akbank.android.apps.akbank_direkt` | 域名类型 |
| `com.akbank.android.apps.akbank_direkt_tablet` | 域名类型 |
| `com.akbank.softotp` | 域名类型 |
| `com.finansbank.mobile.cepsube` | 域名类型 |
| `com.garanti.cepbank` | 域名类型 |
| `com.garanti.cepsubesi` | 域名类型 |
| `com.ingbanktr.ingmobil` | 域名类型 |
| `com.intertech.mobilemoneytransfer.activity` | 域名类型 |
| `com.kuveytturk.mobil` | 域名类型 |
| `com.magiclick.odeabank` | 域名类型 |
| `com.pozitron.iscep` | 域名类型 |
| `com.softtech.isbankasi` | 域名类型 |
| `com.tmob.denizbank` | 域名类型 |
| `com.tmobtech.halkbank` | 域名类型 |
| `com.vakifbank.mobile` | 域名类型 |
| `com.ykb.android.mobilonay` | 域名类型 |
| `com.ykb.androidtablet` | 域名类型 |
| `com.ziraat.ziraatmobil` | 域名类型 |
| `tr.com.sekerbilisim.mbank` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): 发现
3. **银行木马** (CRITICAL): 发现
4. **广告欺诈** (MEDIUM): 发现
5. **蠕虫传播** (HIGH): 发现
