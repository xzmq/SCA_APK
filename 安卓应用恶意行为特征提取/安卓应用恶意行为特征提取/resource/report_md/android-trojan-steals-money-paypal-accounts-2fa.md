# Android Trojan steals money from - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: of this Trojan have been looking for fur
> **恶意软件名称**: Android Trojan steals money from
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
ESET Research
Android Trojan steals money from
PayPal accounts even with 2FA on
ESET researchers discovered a new Android Trojan using a novel Accessibility-abusing
technique that targets the official PayPal app, and is capable of bypassing PayPal’s two-factor
authentication
Lukas Stefanko
11 Dec 2018 • 6 min. read
[Page 2]
[Page 3]
There is a new Trojan preying on Android users, and it has some nasty tricks up its sleeve.
First detected by ESET in November 2018, the malware combines the capabilities of a remotely
controlled banking Trojan with a novel misuse of Android Accessibility 

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

[Page 1]
ESET Research
Android Trojan steals money from
PayPal accounts even with 2FA on
ESET researchers discovered a new Android Trojan using a novel Accessibility-abusing
technique that targets the official PayPal app, and is capable of bypassing PayPal’s two-factor

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: webview

whether this functionality would merely be used as a cover for other malicious actions happening
in the background.
Besides the two core functions described above, and depending on commands received from its
C&C server, the malware can also:
Intercept and send SMS messages; delete all SMS messages; change the default SMS app (to bypass SMS-
based two-factor authentication)
Obtain the contact list

unclear whether the attackers behind this Trojan are also planning to extort money from victims, or
whether this functionality would merely be used as a cover for other malicious actions happening
in the background.
Besides the two core functions described above, and depending on commands received from its
C&C server, the malware can also:
Intercept and send SMS messages; delete all SMS messages; change the default SMS app (to bypass SMS-
based two-factor authentication)

[Page 3]
There is a new Trojan preying on Android users, and it has some nasty tricks up its sleeve.
First detected by ESET in November 2018, the malware combines the capabilities of a remotely
controlled banking Trojan with a novel misuse of Android Accessibility services, to target users of
the official PayPal app.
At the time of writing, the malware is masquerading as a battery optimization tool, and is
distributed via third-party app stores.

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: phishing, overlay

[Page 3]
There is a new Trojan preying on Android users, and it has some nasty tricks up its sleeve.
First detected by ESET in November 2018, the malware combines the capabilities of a remotely
controlled banking Trojan with a novel misuse of Android Accessibility services, to target users of
the official PayPal app.
At the time of writing, the malware is masquerading as a battery optimization tool, and is
distributed via third-party app stores.

[Page 3]
There is a new Trojan preying on Android users, and it has some nasty tricks up its sleeve.
First detected by ESET in November 2018, the malware combines the capabilities of a remotely
controlled banking Trojan with a novel misuse of Android Accessibility services, to target users of
the official PayPal app.
At the time of writing, the malware is masquerading as a battery optimization tool, and is
distributed via third-party app stores.

normally would – but end up being just as vulnerable to this Trojan’s attack as those not using 2FA.
The video below demonstrates this process in practice.
AAnnddrrooiidd TTrroojjaann sstteeaallss mmoonneeyy ffrroomm PPaayyPPaall aaccccoouunnttss eevveenn wwiitthh 22FFAA oonn:: HHooww iitt wwoorrkkss//DDee……
The attackers fail only if the user has insufficient PayPal balance and no payment card connected to
the account. The malicious Accessibility service is activated every time the PayPal app is launched,
meaning the attack could take place multiple times.
We have notified PayPal of the malicious technique used by this Trojan and the PayPal account

### 3.5 勒索软件 (**HIGH**)

• Indicators of Compromise (IoCs)
Figure 5 – Malicious overlay screen for the NAB (National Australia Bank) Mobile Banking app
Unlike overlays used by most Android banking Trojans, these are displayed in lock foreground
screen – a technique also used by Android ransomware. This prevents the victims from removing
the overlay by tapping the back button or the home button. The only way to get past this overlay
screen is to fill out the bogus form, but fortunately, even random, invalid inputs make these screens
disappear.

### 3.6 广告欺诈 (**MEDIUM**)

Figure 2 – Malware requesting the activation of its accessibility service, disguised as “Enable statistics”
If the official PayPal app is installed on the compromised device, the malware displays a notification
alert prompting the user to launch it. Once the user opens the PayPal app and logs in, the malicious
accessibility service (if previously enabled by the user) steps in and mimics the user’s clicks to send
money to the attacker’s PayPal address.
During our analysis, the app attempted to transfer 1000 euros, however, the currency used
depends on the user’s location. The whole process takes about 5 seconds, and for an unsuspecting

### 3.7 蠕虫传播 (**HIGH**)

The malware’s second function utilizes phishing screens covertly displayed over targeted, legitimate
apps.
By default, the malware downloads HTML-based overlay screens for five apps – Google Play,
WhatsApp, Skype, Viber, and Gmail – but this initial list can be dynamically updated at any
moment.
F fth fi l hi hf dit dd t il (Fi 3) th t ti G ili

in the background.
Besides the two core functions described above, and depending on commands received from its
C&C server, the malware can also:
Intercept and send SMS messages; delete all SMS messages; change the default SMS app (to bypass SMS-
based two-factor authentication)
Obtain the contact list

### 3.8 权限滥用 (**HIGH**)

ESET Research
Android Trojan steals money from
PayPal accounts even with 2FA on
ESET researchers discovered a new Android Trojan using a novel Accessibility-abusing
technique that targets the official PayPal app, and is capable of bypassing PayPal’s two-factor
authentication
Lukas Stefanko

meaning the attack could take place multiple times.
We have notified PayPal of the malicious technique used by this Trojan and the PayPal account
used by the attacker to receive stolen funds.
Banking Trojan relying on overlay attacks
The malware’s second function utilizes phishing screens covertly displayed over targeted, legitimate
apps.
By default, the malware downloads HTML-based overlay screens for five apps – Google Play,

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
| `mobi.infolife.uninstaller` | 域名类型 |
| `om.android.cleane` | 域名类型 |
| `om.avira.andro` | 域名类型 |
| `om.barto.uninstalle` | 域名类型 |
| `om.kms.free` | 域名类型 |
| `om.tohsoft.easyuninstalle` | 域名类型 |
| `om.utils.uninstalle` | 域名类型 |
| `oo.util.uninstall` | 域名类型 |
| `service.webview.kiszweb` | 域名类型 |
| `service.webview.strongwebview` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): webview
3. **银行木马** (CRITICAL): phishing, overlay
4. **勒索软件** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
