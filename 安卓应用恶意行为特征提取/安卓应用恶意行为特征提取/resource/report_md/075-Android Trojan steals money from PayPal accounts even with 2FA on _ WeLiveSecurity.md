# [Page 1] - 分析报告

> **来源**: 未知
> **发布日期**: 2018/10/24
> **作者**: of this Trojan have been looking
> **恶意软件名称**: [Page 1]
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
(https://www.welivesecurity.com/) (https://www.eset.com)
Android Trojan steals money from PayPal
accounts even with 2FA on
ESET researchers discovered a new Android Trojan using a novel
Accessibility-abusing technique that targets the official PayPal app,
and is capable of bypassing PayPal’s two-factor authentication
There is a new Trojan preying on Android users, and it has some nasty
tricks up its sleeve.
First detected by ESET in November 2018, the malware combines the
capabilities of a remotely controlled banking Trojan
(https://www.welivesecurity.com/2018/10/24/banking-trojans-
c

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

[Page 1]
(https://www.welivesecurity.com/) (https://www.eset.com)
Android Trojan steals money from PayPal
accounts even with 2FA on
ESET researchers discovered a new Android Trojan using a novel
Accessibility-abusing technique that targets the official PayPal app,

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: webview, config_update

used as a cover for other malicious actions happening in the
background.
Besides the two core functions described above, and depending on
commands received from its C&C server, the malware can also:
Intercept and send SMS messages; delete all SMS messages; change the default
SMS app (to bypass SMS-based two-factor authentication)
Obtain the contact list

used as a cover for other malicious actions happening in the
background.
Besides the two core functions described above, and depending on
commands received from its C&C server, the malware can also:
Intercept and send SMS messages; delete all SMS messages; change the default
SMS app (to bypass SMS-based two-factor authentication)
Obtain the contact list

There is a new Trojan preying on Android users, and it has some nasty
tricks up its sleeve.
First detected by ESET in November 2018, the malware combines the
capabilities of a remotely controlled banking Trojan
(https://www.welivesecurity.com/2018/10/24/banking-trojans-
continue-surface-google-play/) with a novel misuse of Android
Accessibility services, to target users of the official PayPal app.

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

There is a new Trojan preying on Android users, and it has some nasty
tricks up its sleeve.
First detected by ESET in November 2018, the malware combines the
capabilities of a remotely controlled banking Trojan
(https://www.welivesecurity.com/2018/10/24/banking-trojans-
continue-surface-google-play/) with a novel misuse of Android
Accessibility services, to target users of the official PayPal app.

There is a new Trojan preying on Android users, and it has some nasty
tricks up its sleeve.
First detected by ESET in November 2018, the malware combines the
capabilities of a remotely controlled banking Trojan
(https://www.welivesecurity.com/2018/10/24/banking-trojans-
continue-surface-google-play/) with a novel misuse of Android
Accessibility services, to target users of the official PayPal app.

AAnnddrrooiidd TTrroojjaann sstteeaallss mmoonneeyy ffrroomm PPaayyPPaall aaccccoouunnttss eevveenn ww……
(https://www.welivesecurity.com/) (https://www.eset.com)
The attackers fail only if the user has insufficient PayPal balance and no
payment card connected to the account. The malicious Accessibility
service is activated every time the PayPal app is launched, meaning the
attack could take place multiple times.
We have notified PayPal of the malicious technique used by this Trojan

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter, forum

(https://www.welivesecurity.com/2020/02 (https://www.welivesecurity.com/2019/12/

[Page 15]
2-billion-malware-installs-thwarted- percent-android-apps-encrypt-traffic/)
google-play-protect-2019/)
80% of all Android apps encrypt traffic by
(https://www.welivesecurity.com/) (https://www.eset.com)

### 3.5 勒索软件 (**HIGH**)

Banking app
Unlike overlays used by most Android banking Trojans, these are
displayed in lock foreground screen – a technique also used by Android
ransomware. This prevents the victims from removing the overlay by
tapping the back button or the home button. The only way to get past
this overlay screen is to fill out the bogus form, but fortunately, even
random, invalid inputs make these screens disappear.

### 3.6 广告欺诈 (**MEDIUM**)

malware displays a notification alert prompting the user to launch it.
Once the user opens the PayPal app and logs in, the malicious
accessibility service (if previously enabled by the user) steps in and
mimics the user’s clicks to send money to the attacker’s PayPal
address.
During our analysis, the app attempted to transfer 1000 euros,
however, the currency used depends on the user’s location. The whole

### 3.7 蠕虫传播 (**HIGH**)

The malware’s second function utilizes phishing screens covertly
displayed over targeted, legitimate apps.
By default, the malware downloads HTML-based overlay screens for
five apps – Google Play, WhatsApp, Skype, Viber, and Gmail – but this
initial list can be dynamically updated at any moment.

[Page 6]

background.
Besides the two core functions described above, and depending on
commands received from its C&C server, the malware can also:
Intercept and send SMS messages; delete all SMS messages; change the default
SMS app (to bypass SMS-based two-factor authentication)
Obtain the contact list
Make and forward calls

### 3.8 权限滥用 (**HIGH**)

Android Trojan steals money from PayPal
accounts even with 2FA on
ESET researchers discovered a new Android Trojan using a novel
Accessibility-abusing technique that targets the official PayPal app,
and is capable of bypassing PayPal’s two-factor authentication
There is a new Trojan preying on Android users, and it has some nasty
tricks up its sleeve.

attack could take place multiple times.
We have notified PayPal of the malicious technique used by this Trojan
and the PayPal account used by the attacker to receive stolen funds.
Banking Trojan relying on overlay attacks
The malware’s second function utilizes phishing screens covertly
displayed over targeted, legitimate apps.
By default, the malware downloads HTML-based overlay screens for

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `br.com.bb` | 域名类型 |
| `br.com.bb.android` | 域名类型 |
| `com.GoodTools.Uninstalle` | 域名类型 |
| `com.ddm.smartappunsintaller` | 域名类型 |
| `com.jumobile.manager.systemapp` | 域名类型 |
| `com.rhythm.hexise.uninst` | 域名类型 |
| `com.vsrevogroup.revouninstallermobi` | 域名类型 |
| `com.vtm.uninstall` | 域名类型 |
| `com.web.webbrickd` | 域名类型 |
| `com.web.webbrickz` | 域名类型 |
| `jhwgwfj.twjg.ywjgejglijvyesecu1rCit5y5.5cBo3m59` | 域名类型 |
| `mobi.infolife.uninstaller` | 域名类型 |
| `news.drweb.com` | 域名类型 |
| `om.avira.andro` | 域名类型 |
| `om.barto.uninstalle` | 域名类型 |
| `om.kms.free` | 域名类型 |
| `om.tohsoft.easyuninstalle` | 域名类型 |
| `om.utils.uninstalle` | 域名类型 |
| `oo.util.uninstall` | 域名类型 |
| `owmw.awnd.wroeildiv.celseeacnuerity.com` | 域名类型 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `HTTPS://WWW.WELIVESECURITY.COM/CAT` | 钓鱼/下载 |
| `https://eset.com` | 钓鱼/下载 |
| `https://news.drweb.com/show/?i=12980&lng=en` | 钓鱼/下载 |
| `https://owmw.awnd.wroeildiv.celseeacnuerity.com` | 钓鱼/下载 |
| `https://www.eset.com` | 钓鱼/下载 |
| `https://www.paypal.com/cgi-bin/webscr?cmd=_complaint-` | 钓鱼/下载 |
| `https://www.welivesecurity.com` | 钓鱼/下载 |
| `https://www.welivesecurity.com/2018/10/24/banking-trojans-` | 钓鱼/下载 |
| `https://www.welivesecurity.com/2019/12` | 钓鱼/下载 |
| `https://www.welivesecurity.com/2019/12/05` | 钓鱼/下载 |
| `https://www.welivesecurity.com/2020/02` | 钓鱼/下载 |
| `https://www.welivesecurity.com/2020/02/13/almpoerscte-nt-android-apps-encrypt-traffic` | 钓鱼/下载 |
| `https://www.welivesecurity.com/about-` | 钓鱼/下载 |
| `https://www.welivesecurity.com/author/lstefanko` | 钓鱼/下载 |
| `https://www.welivesecurity.com/categories` | 钓鱼/下载 |
| `https://www.welivesecurity.com/category/how-` | 钓鱼/下载 |
| `https://www.welivesecurity.com/contact-` | 钓鱼/下载 |
| `https://www.welivesecurity.com/legal-information` | 钓鱼/下载 |
| `https://www.welivesecurity.com/news-` | 钓鱼/下载 |
| `https://www.welivesecurity.com/our-` | 钓鱼/下载 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): webview, config_update
3. **银行木马** (CRITICAL): phishing, overlay
4. **C2 反检测** (HIGH): twitter, forum
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
