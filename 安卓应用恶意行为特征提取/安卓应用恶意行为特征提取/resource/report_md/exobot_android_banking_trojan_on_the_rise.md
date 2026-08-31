# Sturnus: Mobile Banking Malware bypassing - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Sturnus: Mobile Banking Malware bypassing
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 亚洲
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 恶意广告
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS
CONTACT
RESEARCH
Exobot (Marcher) -
Android banking Trojan
on the rise
01 February 2017
Introduction
Major Milestone:
The past months many different banking Trojans for the Android platform have received media attention.Patent Granted for
One of these, called Marcher (aka Exobot), seems to be especially active with different samples appearing Behavioural Analytics
on a daily basis. This malware var

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, account

out of band authentication for online banks that rely on SMS using SMS forwarding. The second attack
vector, the overlay attack, shows a customized phishing window whenever a targeted application is started
on the device. The overlay window is often indistinguishable from the expected screen (such as a login
screen for a banking app) and is used to steal the victim’s banking credentials. The target list and bank
specific fake login pages can be dynamically updated via their C2 panel (dashboard back-end) which
significantly increases the adaptability and scalability of this attack. In addition, this type of Android
banking malware does not require the device to be rooted or the app to have any specific Android

* com.bitdefender.antivirus (Bitdefender Antivirus Free)
* com.avira.android (Avira Antivirus Security)
* com.ikarus.mobile.security (IKARUS mobile.security)
SMS harvesting
At startup, Marcher will ask for read/write permissions for both SMS and MMS messages if it doesn’t have
the permissions already. Then, whenever the client received command ‘load_sms’ from the C2 server, it
will grab all SMS messages from the device and send them back to the backend. In the same way, this

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: webview, config_update

vector, the overlay attack, shows a customized phishing window whenever a targeted application is started
on the device. The overlay window is often indistinguishable from the expected screen (such as a login
screen for a banking app) and is used to steal the victim’s banking credentials. The target list and bank
specific fake login pages can be dynamically updated via their C2 panel (dashboard back-end) which
significantly increases the adaptability and scalability of this attack. In addition, this type of Android
banking malware does not require the device to be rooted or the app to have any specific Android
permission (besides android.permission.INTERNET to retrieve the overlay contents and send its captured

* com.ikarus.mobile.security (IKARUS mobile.security)
SMS harvesting
At startup, Marcher will ask for read/write permissions for both SMS and MMS messages if it doesn’t have
the permissions already. Then, whenever the client received command ‘load_sms’ from the C2 server, it
will grab all SMS messages from the device and send them back to the backend. In the same way, this
method also is used to invoke ‘processIncomingMessages’ to intercept incoming messages.
Smartly using permissions

∗ android.permission.USES_POLICY_FORCE_LOCK (lock the device)
∗ android.permission.RECEIVE_BOOT_COMPLETED (start malware when device boots)
∗ android.permission.INTERNET (communicate with the internet)
∗ android.permission.VIBRATE (control the vibrator)
∗ android.permission.ACCESS_WIFI_STATE (view information about the status of Wi-Fi)
∗ android.permission.WRITE_SMS (edit/delete SMS)
∗ android.permission.ACCESS_NETWORK_STATE (view the status of all networks)

### 3.3 银行木马 (**CRITICAL**)

**涉及技术**: app_replace, phishing, overlay

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS

### 3.4 C2 反检测 (**HIGH**)

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS
CONTACT
RESEARCH

### 3.5 勒索软件 (**HIGH**)

When the malware first runs, it will ask for device administrative rights, even when users deny or kill the
process it will come up again, until they accept the request. Having this permission enables malware to
lock and mute the phone, even reset the password and make a permanent phishing WebView. This
malicious activity works similar to ransomware, but no files are encrypted.

[Page 12]
Device admin “nagging” screen

### 3.6 广告欺诈 (**MEDIUM**)

Users should avoid downloading apps from a third-party and only use Google Play Store (so do not
enable installation from unknown sources). Take note however that even in the Google Play Store apps are
not necessarily malware free. Check if the requested privileges correspond with the expected privileges of
the app you want to install. Also, never click on a suspicious link in SMS and email messages even it is
from trusted contacts.
Conclusion
Marcher is growing into a mature Trojan with solid organization behind it like many of the banking

### 3.7 蠕虫传播 (**HIGH**)

[Page 1]
Sturnus: Mobile Banking Malware bypassing
Read Article
WhatsApp, Telegram & Signal Encryption
OOUURR SSOOLLUUTTIIOONNSS PPAARRTTNNEERRSS WWEEBBIINNAARRSS AARRTTIICCLLEESS RREESSOOUURRCCEESS
CONTACT
RESEARCH

* com.facebook.katana (Facebook)
* com.skype.raider (Skype)
* com.viber.voip (Viber)
* com.whatsapp (WhatsApp Messenger)

[Page 10]
* com.google.android.gm (Gmail)

compared to the previous Android versions to prevent such attacks.

[Page 2]
The main infection vector is a phishing attack using SMS/MMS. The social engineering message includes a
link that leads to a fake version of a popular app, using names like Runtastic, WhatsApp or Netflix. On
installation, the app requests the user to provide SMS storage access and high Android privileges such as
Device Admin. Other infection vectors include pornographic websites serving apps called Adobe Flash or

### 3.8 权限滥用 (**HIGH**)

One of these, called Marcher (aka Exobot), seems to be especially active with different samples appearing Behavioural Analytics
on a daily basis. This malware variant also appears to be technically superior to many other banking
LEARN MORE
Trojans being able to use its overlay attack even on Android 6, which has technical improvements
compared to the previous Android versions to prevent such attacks.

[Page 2]

screen for a banking app) and is used to steal the victim’s banking credentials. The target list and bank
specific fake login pages can be dynamically updated via their C2 panel (dashboard back-end) which
significantly increases the adaptability and scalability of this attack. In addition, this type of Android
banking malware does not require the device to be rooted or the app to have any specific Android
permission (besides android.permission.INTERNET to retrieve the overlay contents and send its captured
data).
The many changes we see in the way the attacks are performed show that attackers are heavily

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `176.119.28.74` | 域名类型 |
| `android.permission.ACCESS_NETWORK_STATE` | 域名类型 |
| `android.permission.ACCESS_WIFI_STATE` | 域名类型 |
| `android.permission.CALL_PHONE` | 域名类型 |
| `android.permission.CHANGE_NETWORK_STATE` | 域名类型 |
| `android.permission.CHANGE_WIFI_STATE` | 域名类型 |
| `android.permission.GET_TASKS` | 域名类型 |
| `android.permission.INTERNET` | 域名类型 |
| `android.permission.READ_CONTACTS` | 域名类型 |
| `android.permission.READ_PHONE_STATE` | 域名类型 |
| `android.permission.READ_SMS` | 域名类型 |
| `android.permission.RECEIVE_BOOT_COMPLETED` | 域名类型 |
| `android.permission.RECEIVE_SMS` | 域名类型 |
| `android.permission.SEND_SMS` | 域名类型 |
| `android.permission.USES_POLICY_FORCE_LOCK` | 域名类型 |
| `android.permission.VIBRATE` | 域名类型 |
| `android.permission.WAKE_LOCK` | 域名类型 |
| `android.permission.WRITE_SETTINGS` | 域名类型 |
| `android.permission.WRITE_SMS` | 域名类型 |
| `ar.com.santander.rio.mbanking` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `176.119.28.74` | 服务器 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `25e07c50707c77c8656088a9a7ff3fdd9552b5b8022d8c154f73dca1e631db4f` | 恶意文件 |
| `5a9e3d2c2ef29b76c628e70a91575dc4be3999b60f34cab35ee70867faaff4a0` | 恶意文件 |
| `5bb9b9173496d8b70093ef202ed0ddddd48ad323e594345a563a427c1b2ebc22` | 恶意文件 |
| `5df132235eccd1e75474deca5b95e59e430e23a22f68b6b27c2c3a4aeb748857` | 恶意文件 |
| `6f8b7aa6293238d23b1c5236d1c10cecc54ec8407007887e99ea76f9fce51075` | 恶意文件 |
| `7f08cc20aa6e1256f6a8db3966ac71ad209db6dff14a6dde0fd7b2407c2c23e7` | 恶意文件 |
| `a1258e57c013385401d29b75cf4dc1559691d1b2a9afdab804f07718d1ba9116` | 恶意文件 |
| `b087728f732ebb11c4a0f06e02c6f8748d621b776522e8c1ed3fb59a3af69729` | 恶意文件 |
| `b4e5affbc3ea94eb771614550bc83fde85f90caddcca90d25704c9a556f523da` | 恶意文件 |
| `be6c8a4afbd4b31841b2d925079963f3bd5422a5ee5f248c5ed5013093c21cf9` | 恶意文件 |
| `c172567ccb51582804e589afbfe5d9ef4bc833b99b887e70916b45e3a113afb8` | 恶意文件 |
| `c8f753904c14ecee5d693ce454353b70e010bdaf89b2d80c824de22bd11147d5` | 恶意文件 |
| `ec4d182b0743dbdedb989d4f4cb2d607034ee1364c30103b2415ea8b90df8775` | 恶意文件 |
| `ed2b26c9cf4bc458c2fa89476742e9b0d598b0c300ab45e5211f29dfd9ddd67b` | 恶意文件 |
| `f7743a01fc80484242d59868938ec64990c19bea983fb58b653822c9ee3306a1` | 恶意文件 |
| `fcd18a2b174a9ef22cd74bb3b727a11b4c072fcef316aefbb989267d21d8bf7d` | 恶意文件 |

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
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 即时通讯软件传播, 恶意广告 |
| **综合风险** | **CRITICAL** | 检测到8类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, account
2. **远程控制** (CRITICAL): webview, config_update
3. **银行木马** (CRITICAL): app_replace, phishing, overlay
4. **C2 反检测** (HIGH): 发现
5. **勒索软件** (HIGH): 发现
9. 其他行为见详细信息...
