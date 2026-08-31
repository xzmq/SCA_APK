# CSIS TechBlog - 分析报告

> **来源**: 未知
> **发布日期**: Sep 3, 2019
> **作者**: ization codes for premium
> **恶意软件名称**: CSIS TechBlog
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 中国, 美国, 泰国, 土耳其, 巴西
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
CSIS TechBlog
Analysis of Joker — A Spy &
Premium Subscription Bot on
GooglePlay
Be the first to hear about new stories
from Aleksejs Kuprins
Aleksejs Kuprins Follow 9 min read · Sep 3, 2019
Join Medium for free to get updates from Aleksejs Kuprins sent right
to your inbox.
574 3
Your email
Enter your email address
Over the past couple of weeks, we have been observing a new Trojan on
Remember me for faster sign in
GooglePlay. So far, we have detected it in 24 apps with over 472,000+ installs
in total. The malware — going by the name “the Joker” (which was borrowed
Create account
from 

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account, device_info

in total. The malware — going by the name “the Joker” (which was borrowed
Create account
from one of the C&C domain names) — delivers a second stage component,
which silently simulates the intOetrhaerc stiigonn u pw opitthion asdvertisement websites, steals
the victim’s SMS messages, the contact list and device info.
Already have an account? Sign in
The automatedB yi cnlictkeinrga "Ccretaitoe Ancc wounitt",h yo ut hacece pat Mdevdeiumrt'si Tseermms oef Snertvi cwe aendb Psriivtaceys P oilincyc. ludes

contact list and sends them over to the C&C in an encrypted form:
Remember me for faster sign in
Already have an account?
Contact list harvesting
By clicking "Create Account", you accept Medium's Terms of Service and Privacy Policy.
This site uses reCaptcha and the Google Privacy Policy and Terms of Service apply.
A total of 12 unique builds of the second stage payload were observed among

This site uses reCaptcha and the Google Privacy Policy and Terms of Service apply.

[Page 8]
Joker’s SMS data exfiltration, encrypted with AES
The figure above is a sample of the second stage communication with the
C&C and it contains the full text of a stolen test SMS message. It can be
decrypted into a JSON object. The clear-text communication can also be

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

14
Your email
SHA256:
81d784ee65a8dc113683cd7cc271a36da275a500621cefa187095951af3a5114
Package Name: com.building.castle.bster
Installs: 50,000+
Loader Path: com.startapp.android.publish

GooglePlay. So far, we have detected it in 24 apps with over 472,000+ installs
in total. The malware — going by the name “the Joker” (which was borrowed
Create account
from one of the C&C domain names) — delivers a second stage component,
which silently simulates the intOetrhaerc stiigonn u pw opitthion asdvertisement websites, steals
the victim’s SMS messages, the contact list and device info.
Already have an account? Sign in

Slovenia, Spain, Sweden, Switzerland, Thailand, Turkey, Ukraine, United
Arab Emirates, United Kingdom and United States.
Besides loading the second stage DEX file, the malware also receives
dynamic code and commands over HTTP and runs that code via JavaScript-
to-Java callbacks. Such an approach provides an extra layer of protection
against static analysis, since a lot of instructions in this case are not hard-
coded into the malicious app on GooglePlay.

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

• Target country checking via MCC
Your email
• Minimum C&C communication — just enough to report the infection and
receive the encrypted configuration
• DEX decryption & loading
Remember me for faster sign in
• A notification listener — when a new SMS message arrives, this listener

### 3.6 广告欺诈 (**MEDIUM**)

Already have an account? Sign in
The automatedB yi cnlictkeinrga "Ccretaitoe Ancc wounitt",h yo ut hacece pat Mdevdeiumrt'si Tseermms oef Snertvi cwe aendb Psriivtaceys P oilincyc. ludes
This site uses reCaptcha and the Google Privacy Policy and Terms of Service apply.
simulation of clicks and entering of the authorization codes for premium
service subscriptions. For example, in Denmark, Joker can silently sign the
victim up for a 50 DKK/week service (roughly ~6,71 EUR). This strategy works
by automating the necessary interaction with the premium offer’s webpage,

### 3.7 蠕虫传播 (**HIGH**)

e44f514c7729a6c39700db6ac51c817c77741e19178f8942c2d26f6b62ef9df5
Package Name: com.declare.smsarr.message
Installs: 10,000+
Loader Path: com.messages.messenger.chat.list
SHA256:
226e9c5ca45facb9b9a36529e09958546c4b351f4b7ae02101f8e3c1d6e3de7b
Be the first to hear about new stories

Create account
from one of the C&C domain names) — delivers a second stage component,
which silently simulates the intOetrhaerc stiigonn u pw opitthion asdvertisement websites, steals
the victim’s SMS messages, the contact list and device info.
Already have an account? Sign in
The automatedB yi cnlictkeinrga "Ccretaitoe Ancc wounitt",h yo ut hacece pat Mdevdeiumrt'si Tseermms oef Snertvi cwe aendb Psriivtaceys P oilincyc. ludes
This site uses reCaptcha and the Google Privacy Policy and Terms of Service apply.

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `3.122.143` | 域名类型 |
| `3.122.143.26` | 域名类型 |
| `47.254.144` | 域名类型 |
| `com.Climate.sms` | 域名类型 |
| `com.Ignite.amino.clean` | 域名类型 |
| `com.alc.coolermaster.activity.create` | 域名类型 |
| `com.anti.mysecurity` | 域名类型 |
| `com.blur.blurphoto.view` | 域名类型 |
| `com.board.picture.editing` | 域名类型 |
| `com.building.castle.bster` | 域名类型 |
| `com.burning.rockn.scan` | 域名类型 |
| `com.cantwait.ezlife.wallpaper` | 域名类型 |
| `com.certain.icdesktop.wallpaper` | 域名类型 |
| `com.change.nicephoto` | 域名类型 |
| `com.color.black.filter` | 域名类型 |
| `com.comeback.myside.sms` | 域名类型 |
| `com.cute.hd4kcam.camera` | 域名类型 |
| `com.declare.smsarr.message` | 域名类型 |
| `com.facebook.appevents.camera.pics` | 域名类型 |
| `com.fungo.constellation.common.ball` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `3.122.143.26` | 服务器 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `0eba66cda54c732645ca69949882097c2f2e69dff917e8834b6636ef00848772` | 恶意文件 |
| `162ee177dea9b94366063de63dffd97f92f7a50e0e429d54fea73dc3a52f1b3a` | 恶意文件 |
| `1e724a5af76927106ee92421412af62698707d1d44a9891f91b3c6902f1780cd` | 恶意文件 |
| `226e9c5ca45facb9b9a36529e09958546c4b351f4b7ae02101f8e3c1d6e3de7b` | 恶意文件 |
| `27450c3c735dc3dcba9254a3b08ed22bbcde8631343cb70107d4e41e17fbb548` | 恶意文件 |
| `2d9a7d75227c3332591e1af5a2f2223eec3328c75c95dea9a33ea269200faf38` | 恶意文件 |
| `2e3bff9dda4c568a5e12c2f468227ec8dc5baf9913fe573f02ef2d5432b37bc0` | 恶意文件 |
| `43b36c438a3531e42623fbd00f5b57066a4db8048ce8e0ab0b5ecf9eac67aabf` | 恶意文件 |
| `494c8c6155a08ae95a2f1962636911310c98d36f065e81eddf4ffcb172913495` | 恶意文件 |
| `5405e39dbde78e3b561a6e54f208ce557f04bdbdc363ea6442892d26ba91811e` | 恶意文件 |
| `54aba1530d829c71b2410c06628de034e38bc52be3002f82cc771c219d91958d` | 恶意文件 |
| `6261be516a54d8566348b8305e96f34bdbf4f11620350c5f36f4bc3cb67fc181` | 恶意文件 |
| `65135899349daca2646ca36c5a442382bc988f5b3749a2bd5322170d777af77a` | 恶意文件 |
| `69d94f94233a2e42d49eeafaea7bf2aad86671cdaf3be45b00ff3de624d7e883` | 恶意文件 |
| `718210a0c41160240843711d79f2757548e72934e996b0e16a2b2277369d366b` | 恶意文件 |
| `81d784ee65a8dc113683cd7cc271a36da275a500621cefa187095951af3a5114` | 恶意文件 |
| `9b4a1b7c638be029f0ffcb92dcfac74052f41fc36d43a45f6aa80d20d1285646` | 恶意文件 |
| `a7dc4238682147012751bb853001b053527ca8031a624bbd5db1a77a3e563ead` | 恶意文件 |
| `a8bf4055a4988ee181be9915c93c6278503be562475a558aef3c6dba54e06b13` | 恶意文件 |
| `b36fbe6b75f00ae835156185ca5d6955cdfbe410d73c3e5653dabbaff260f166` | 恶意文件 |
| `b631b2254850e62804fc66895850dcbf007d670aa843af8d2e525c85947da2d4` | 恶意文件 |
| `befde4166a9cdf2ff7c8f81fb5dec6a6760d20e0debbc667a8274899a248ef31` | 恶意文件 |
| `da2171a32f3b95620c35a48a34fb7293a321ab41266d3461f808b2f07694e5a7` | 恶意文件 |
| `e44f514c7729a6c39700db6ac51c817c77741e19178f8942c2d26f6b62ef9df5` | 恶意文件 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `https://s3.amazonaws.com/media.site-group-df[.]com/s8-release` | 钓鱼/下载 |
| `https://tb-eu-jet.oss-eu-central-1.aliyuncs.com/s8-` | 钓鱼/下载 |
| `https://twitter.com/s_metanka` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): twitter
4. **广告欺诈** (MEDIUM): 发现
5. **蠕虫传播** (HIGH): 发现
