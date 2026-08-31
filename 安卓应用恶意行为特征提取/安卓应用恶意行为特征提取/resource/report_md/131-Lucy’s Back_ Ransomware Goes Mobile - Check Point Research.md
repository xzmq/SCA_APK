# [Page 1] - 分析报告

> **来源**: Check Point
> **发布日期**: 未知
> **作者**: Ohad Mana
> **恶意软件名称**: [Page 1]
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
(HTTPS://WWW.FACEBOOK.COM/CHECKPOINTRESEARCH/)
CHECKPOINT.COM (HTTPS://WWW.CHECKPOINT.COM)
(HTTPS://PLUS.GOOGLE.COM/+CHECKPOINT/POSTS)
(HTTPS://WWW.LINKEDIN.COM/COMPANY/CHECK-POINT-SOFTWARE-TECHNOLOGIES)
(MAILTO:?
(https://research.checkpoint.com/)
TO=& (HSTUTBPJSE:C//TR=ERSEESAERACRHC.HC.HCEHCEKCPKOPIONITN.CT.OCMO/MF&EBEDO)DY=C H(HETCTKPOSU:/T/T%W20ITTTHEER%.C2O0MLA/_TCESPTR%ES20ERAERSCEHA_R)CH%20ON%20RESEARCH.CHECKPOINT.COM!)
PUBLICATIONS (HTTPS://RESEARCH.CHECKPOINT.COM/CATEGORY/THREAT-RESEARCH/) TOOLS
ABOUT US (HTTPS://RESEARCH.CHECKPOINT.COM/ABOUT-US/) CONTACT US (HTTPS://RESEARC

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

(HTTPS://WWW.LINKEDIN.COM/COMPANY/CHECK-POINT-SOFTWARE-TECHNOLOGIES)
(MAILTO:?
(https://research.checkpoint.com/)
TO=& (HSTUTBPJSE:C//TR=ERSEESAERACRHC.HC.HCEHCEKCPKOPIONITN.CT.OCMO/MF&EBEDO)DY=C H(HETCTKPOSU:/T/T%W20ITTTHEER%.C2O0MLA/_TCESPTR%ES20ERAERSCEHA_R)CH%20ON%20RESEARCH.CHECKPOINT.COM!)
PUBLICATIONS (HTTPS://RESEARCH.CHECKPOINT.COM/CATEGORY/THREAT-RESEARCH/) TOOLS
ABOUT US (HTTPS://RESEARCH.CHECKPOINT.COM/ABOUT-US/) CONTACT US (HTTPS://RESEARCH.CHECKPOINT.COM/CONTACT/)
SUBSCRIBE (HTTPS://RESEARCH.CHECKPOINT.COM/SUBSCRIPTION/)

called by the command action.SCREEN_ON and then calls itself. This is used to acquire the ‘WakeLock’ service, which keeps
the device’s screen on, and ‘WifiLock’ service, which keeps the WIFI on.
Communication:
The malware has 4 encrypted command and control (C&C) servers in its code. Unlike previous versions of the malware, the
C&C is a domain and not an IP address. Therefore, although the server can be taken down, it can easily be resolved into a new
IP address, which makes it much harder to neutralize the malware.
The C&C servers are held as a long string which is a concatenation of all C&Cs hardcoded in the malware’s code, followed by a

Lucy then tries to trick the victim into enabling the Accessibility Service by initiating an Alert Dialog that asks the user to take
action.
Inside the MainActivity module, the application triggers the malicious service, which then registers a BroadcastReceiver that is
called by the command action.SCREEN_ON and then calls itself. This is used to acquire the ‘WakeLock’ service, which keeps
the device’s screen on, and ‘WifiLock’ service, which keeps the WIFI on.
Communication:
The malware has 4 encrypted command and control (C&C) servers in its code. Unlike previous versions of the malware, the

An example is the ‘Black Rose Lucy’ malware family, originally discovered in September 2018 by Check Point
(https://research.checkpoint.com/2018/meet-black-rose-lucy-the-latest-russian-maas-botnet/). Lucy is a Malware-as-a-
Service (MaaS) botnet and dropper for Android devices. And now, nearly two years later, it is back with new ransomware
capabilities that allow it to take control of victims’ devices to make various changes and install new malicious applications.
When downloaded, Lucy now encrypts files on the infected device and displays a ransom note in the browser window which
claims to be an official message from the US FBI, accusing the victim of possessing pornographic content on his device. The
message also states that as well as locking the device, the user’s details have been uploaded to the FBI Cyber Crime

### 3.3 银行木马 (**CRITICAL**)

[Page 4]
Decrypt
Similar to ‘GetCrypt’ but used for decryption.
Declines previous payment – shows a
GetCont
message that the payment was declined.
Sends a list of all installed applications to the

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

(https://research.checkpoint.com/2018/meet-black-rose-lucy-the-latest-russian-maas-botnet/). Lucy is a Malware-as-a-
Service (MaaS) botnet and dropper for Android devices. And now, nearly two years later, it is back with new ransomware
capabilities that allow it to take control of victims’ devices to make various changes and install new malicious applications.
When downloaded, Lucy now encrypts files on the infected device and displays a ransom note in the browser window which
claims to be an official message from the US FBI, accusing the victim of possessing pornographic content on his device. The
message also states that as well as locking the device, the user’s details have been uploaded to the FBI Cyber Crime

### 3.5 勒索软件 (**HIGH**)

SERVICES/THREATCLOUD-
INCIDENT-
RESPONSE/)
Lucy’s Back: Ransomware Goes Mobile
April 28, 2020
Research by: Ohad Mana, Aviran Hazum, Bogdan Melnykov, Liav Kuperman
Overview

### 3.6 广告欺诈 (**MEDIUM**)

The Android operating system only allows users to carry out a manual configuration to enable an application to have device
administrator privileges. It explicitly asks for user consent in a pop-up window, or asks the user to navigate through a series of
system settings before such privileges are granted.
However, the Android accessibility service, which mimics a user’s screen clicks and has the ability to automate user
interactions with the device, could be used by malware to get around these security restrictions. Accessibility services are
normally used to allow users to automate and simplify certain repeated tasks. With Lucy, it’s the Achilles Heel in the Android’s
defensive armour.

### 3.7 蠕虫传播 (**HIGH**)

wcqrucdpzh.otstodvvsm.vrbnjqrsrr 36b4ad5ece2a6fbcdf011ac08dd48f584a96cab09d4e3e0542b5b9b46a318244
wcqrucdpzh.otstodvvsm.vrbnjqrsrr d9866310eab9463f54703bb5c105c09b272205b0904ea9bd7f1ed2947022abcb
RELATED ARTICLES
Fuzzing the Office Ecosystem New Wormable Android Malware Vulnerability in Google Play Core Graphol
Spreads by Creating Auto-Replies to Library Remains Unpatched in Google exploits
1/cyber- (//research.checkpoint.com/2021/fuzzing-
Messages in WhatsApp Play Applications fingerpr

wcqrucdpzh.otstodvvsm.vrbnjqrsrr d9866310eab9463f54703bb5c105c09b272205b0904ea9bd7f1ed2947022abcb
RELATED ARTICLES
Fuzzing the Office Ecosystem New Wormable Android Malware Vulnerability in Google Play Core Graphol
Spreads by Creating Auto-Replies to Library Remains Unpatched in Google exploits
1/cyber- (//research.checkpoint.com/2021/fuzzing-
Messages in WhatsApp Play Applications fingerpr
PUBLICATIONS

Fuzzing the Office Ecosystem New Wormable Android Malware Vulnerability in Google Play Core Graphol
Spreads by Creating Auto-Replies to Library Remains Unpatched in Google exploits
1/cyber- (//research.checkpoint.com/2021/fuzzing-
Messages in WhatsApp Play Applications fingerpr
PUBLICATIONS
GLOBAL CYBER ATTACK REPORTS (HTTPS://RESEARCH.CHECKPOINT.COM/CATEGORY/THREAT-INTELLIGENCE-REPORTS/)
RESEARCH PUBLICATIONS (HTTPS://RESEARCH.CHECKPOINT.COM/CATEGORY/THREAT-RESEARCH/)

### 3.8 权限滥用 (**HIGH**)

The Android operating system only allows users to carry out a manual configuration to enable an application to have device
administrator privileges. It explicitly asks for user consent in a pop-up window, or asks the user to navigate through a series of
system settings before such privileges are granted.
However, the Android accessibility service, which mimics a user’s screen clicks and has the ability to automate user
interactions with the device, could be used by malware to get around these security restrictions. Accessibility services are
normally used to allow users to automate and simplify certain repeated tasks. With Lucy, it’s the Achilles Heel in the Android’s
defensive armour.

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `co1m.andr53oid.gohpat` | 域名类型 |
| `dtlrquunob.ntrbhppvnr.dbawnbxoxz` | 域名类型 |
| `en.wikipedia.org` | 域名类型 |
| `gcoojdprtw.tsqrstjtdi.crwrnqoqur` | 域名类型 |
| `research.checkpoint.com` | 域名类型 |
| `tpviytfsqr.kbnsbdnudm.tswponqgfg` | 域名类型 |
| `uuctvbgtlb.nkoqrtdctt.unootbawgh` | 域名类型 |
| `wcqrucdpzh.otstodvvsm.vrbnjqrsrr` | 域名类型 |
| `www.checkpoint.com` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `02cfbe349d6e9c57286121ee727260f7effba00e765053ad38ca03bd44936a57` | 恶意文件 |
| `05bbe4182b890c91ff96ef7bf39e5dd94feae83d5067ccdc9703a05278b9983d` | 恶意文件 |
| `0a5a317859cc0cb52fbf80cb8fce9916cc113193fb56231711cc83a44601ba91` | 恶意文件 |
| `0ac1a48c7b3d17afb258be9f0fcb03720129d9939f7fbac741dbb6042012045a` | 恶意文件 |
| `0b213d7deb41b262638adcfce47048e61f949749f688e6440c4951646710f8b3` | 恶意文件 |
| `1163d9d45b57fa267044bede0ca3493c1bae3e604f632f348f28107566036fcf` | 恶意文件 |
| `1604634cf52ca567c4121d6f11ba1a5166961da65e18098685c404d1eca36002` | 恶意文件 |
| `20acb6c9de4eb8764a7d91034c4065adb0b9e5f7afb8183ff9abc1d09bff20fd` | 恶意文件 |
| `2257eaa9788d8f0ae55a2d85794a3db82155a4586a29abab93c9ef61ab9bcb01` | 恶意文件 |
| `283892cbf8ff13ddf499835185d54bb2fa4c86864eaecf5de231c67f6d14da82` | 恶意文件 |
| `2e5c0b796c4830f11066e8c78fb215ac0a1bb555ca0d89973c7c40a046b99d0c` | 恶意文件 |
| `2ee564b1f97546342ebeff6e763702b65de61f8889203ccb95d41b3e80168269` | 恶意文件 |
| `3144526d354e29e5cc3985a8f06513627b98441d6db745b96fe85e78bf17b066` | 恶意文件 |
| `3688e2fd329263b77000533f2263ab823755165ac32c12e8087096caac6634e7` | 恶意文件 |
| `36b4ad5ece2a6fbcdf011ac08dd48f584a96cab09d4e3e0542b5b9b46a318244` | 恶意文件 |
| `3ad1aa75f699be78c20a2aa7ab94f30186896d7adee10617b02448fa5e5c08fe` | 恶意文件 |
| `3afb57ed431dd88bcf82203fa4f19c9164eae672768f87153334813bae91fee1` | 恶意文件 |
| `3ea8579928b7f671e7df8637a7bd9b5d4fbf4e1b7bdeea2cc3c62b23ea0e9b96` | 恶意文件 |
| `436f08e1fe0fc9d666f61b9e6a4f50311f867d3c878876b93e3cfebf88bf5362` | 恶意文件 |
| `4c6c04fc22e19dc5d1de7237da6f0d3cdddfeb655be957b6e592ef91c74fd71c` | 恶意文件 |
| `4c8f0810c0071d199af5b1ab1a332a239a536ab96152abf5445bdee11e77e87d` | 恶意文件 |
| `5604a3fde8dd61691313e6812f13143d093d58b8047f07489f5d2b0e5490b6bf` | 恶意文件 |
| `57d9420ac144d2a62fddb4959a405de1243bc75f7b579abb4489c1ea16320b35` | 恶意文件 |
| `5bbe9e80288991de75fb7d4f1b2ea3a87cfcbd2a64a3e2b13861535cccecd136` | 恶意文件 |
| `5c2333a7a5fcc71ec16d02a48134981cfe7ecfc2ddb8114ef46c57af0eccd4ef` | 恶意文件 |
| `5c6f4b0ffcb31f4d10c9c1e95f298f8cf8b3a1a97a2272e540fed0cca4829bbf` | 恶意文件 |
| `67a592cb8ba37d1340bb8bbda13397c827e07b71066ec86eb709324652b8771c` | 恶意文件 |
| `67d99c5f4233ae02b21d8cb6e72203372ae3b7a2a12bbe2bf419a70aee1a0984` | 恶意文件 |
| `6b0ddf78efc98c1fe34ac7500be38254ee57cc4d436a51b5943c8851e4d46128` | 恶意文件 |
| `70fef3fd8100b8ede14b4cb37cc2b2c6baa208920bd345439a2a19c1d47a1618` | 恶意文件 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `HTTP://BLOG.CHECKPOINT.COM` | 钓鱼/下载 |
| `HTTP://WWW.CPCHECKME.COM/CHECKME` | 钓鱼/下载 |
| `HTTPS://PLUS.GOOGLE.COM/+CHECKPOINT/POSTS` | 钓鱼/下载 |
| `HTTPS://RESEARCH.CHECKPOINT.COM/ABOUT-US` | 钓鱼/下载 |
| `HTTPS://RESEARCH.CHECKPOINT.COM/CATEGORY/DEMOS` | 钓鱼/下载 |
| `HTTPS://RESEARCH.CHECKPOINT.COM/CATEGORY/THREAT-INTELLIGENCE-REPORTS` | 钓鱼/下载 |
| `HTTPS://RESEARCH.CHECKPOINT.COM/CATEGORY/THREAT-RESEARCH` | 钓鱼/下载 |
| `HTTPS://RESEARCH.CHECKPOINT.COM/CONTACT` | 钓鱼/下载 |
| `HTTPS://RESEARCH.CHECKPOINT.COM/SUBSCRIPTION` | 钓鱼/下载 |
| `HTTPS://THREATEMULATION.CHECKPOINT.COM` | 钓鱼/下载 |
| `HTTPS://THREATMAP.CHECKPOINT.COM/THREATPORTAL/LIVEMAP.HTML` | 钓鱼/下载 |
| `HTTPS://WWW.CHECKPOINT.COM` | 钓鱼/下载 |
| `HTTPS://WWW.CHECKPOINT.COM/ADVISORIES` | 钓鱼/下载 |
| `HTTPS://WWW.CHECKPOINT.COM/SUPPORT-` | 钓鱼/下载 |
| `HTTPS://WWW.CHECKPOINT.COM/URLCAT` | 钓鱼/下载 |
| `HTTPS://WWW.FACEBOOK.COM/CHECKPOINTRESEARCH` | 钓鱼/下载 |
| `HTTPS://WWW.LINKEDIN.COM/COMPANY/CHECK-POINT-SOFTWARE-TECHNOLOGIES` | 钓鱼/下载 |
| `https://en.wikipedia.org/wiki/CryptoLocker` | 钓鱼/下载 |
| `https://research.checkpoint.com` | 钓鱼/下载 |
| `https://research.checkpoint.com/2018/meet-black-rose-lucy-the-latest-russian-maas-botnet` | 钓鱼/下载 |

### 社交媒体

| 账号 | 用途 |
|------|------|
| @sh1shk0va | C2/通信 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): config_update
2. **银行木马** (CRITICAL): 发现
3. **C2 反检测** (HIGH): twitter
4. **勒索软件** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
