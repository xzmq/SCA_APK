# By Dario Durando| June 03, 2018 - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: of the malware has encouraged
> **恶意软件名称**: By Dario Durando| June 03, 2018
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 日本
| 活动时间 | 未知
| 传播方式 | 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
FFOORRTTIIGGUUAARRDD LLAABBSS TTHHRREEAATT RREESSEEAARRCCHH
AAnnddrrooiidd SSppyywwaarree NNooww DDrrooppppiinngg LLeeggiitt AAppppss??
By Dario Durando| June 03, 2018
[Page 2]
Recently, Zscaler released a blogpost about Android malware impersonating the mobile version of the very popular game Fortnite. The game is
currently supported on PC, PlayStation 4, and iOS, but does not offer an Android alternative, making it very attractive for potential malicious actors,
as does the young age of a large portion of the audience of this game.
FortiGuard Labs tracked these samples as well. The 

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account

Nonetheless, even though this technique makes the spyware easily detectable by security software, it is actually quite efficient at tricking someone
who is not an expert.
Conclusions
This malware may not be the most advanced Android malware around, but it is still able to steal a large amount of sensitive information from an
infected device. In addition, while this spyware is currently dropping benign apps to hide itself, it could just as easily drop some other malicious apk.
Instead, it leverages the popularity of other apps to spread through third party apk markets.
An Additional Consideration:

Send and receive SMS
Access contacts
Make calls
Harvest call logs
There were, however, a couple of other things happening under the hood. Which is why we decided to write down what we found to provide a
clearer picture.
For this analysis, we are going to refer to sample 5e9b28f53c008225f9e4174f4c2db6a03cd7e7fe77438d3f134bbd592e2d99e3

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

Harvest call logs
There were, however, a couple of other things happening under the hood. Which is why we decided to write down what we found to provide a
clearer picture.
For this analysis, we are going to refer to sample 5e9b28f53c008225f9e4174f4c2db6a03cd7e7fe77438d3f134bbd592e2d99e3
Analysis
We noticed that a lot of apks using the same package name “yps.eton.application” were also sporting the same code. This did not surprise us, as
malicious actors often repackage the same malicious code with different icons and names. All of them were also signed with the same certificate. A

Based on the figures above we can see that in this case the spyware was designed to hide its icon and have the main functionalities active, and as
we experienced during testing, no Device admin was actually requested. The ‘group_properties’ string found in the FortNite sample we analyzed
was “11001111”, which makes it a much more aggressive version.
It is relatively unusual to have these strings hardcoded in the app. It would make more sense to retrieve these from a Command and Control server,
as these hardcoded strings cannot be modified at run time. Moreover, because these apps are found on third party marketplaces, this approach
also denies them the possibility of receiving updates that could modify them.
Another thing we noticed was its access to a resource called “R.raw.google”. In the Fortnite sample, this resource, called “google.apk”, existed, but

Based on the figures above we can see that in this case the spyware was designed to hide its icon and have the main functionalities active, and as
we experienced during testing, no Device admin was actually requested. The ‘group_properties’ string found in the FortNite sample we analyzed
was “11001111”, which makes it a much more aggressive version.
It is relatively unusual to have these strings hardcoded in the app. It would make more sense to retrieve these from a Command and Control server,
as these hardcoded strings cannot be modified at run time. Moreover, because these apps are found on third party marketplaces, this approach
also denies them the possibility of receiving updates that could modify them.
Another thing we noticed was its access to a resource called “R.raw.google”. In the Fortnite sample, this resource, called “google.apk”, existed, but

### 3.5 勒索软件 (**HIGH**)

Threat Research
FortiGuard Labs
Threat Map
Ransomware Prevention
Connect With Us
Fortinet Community
Partner Portal

### 3.7 蠕虫传播 (**HIGH**)

Conclusions
This malware may not be the most advanced Android malware around, but it is still able to steal a large amount of sensitive information from an
infected device. In addition, while this spyware is currently dropping benign apps to hide itself, it could just as easily drop some other malicious apk.
Instead, it leverages the popularity of other apps to spread through third party apk markets.
An Additional Consideration:
Over the past month there has been a surge in videos on YouTube advertising fictitious Fortnite apps for Android. It is an extremely popular game,
and a very large percentage of the users are young kids that can be tricked into downloading anything in order to play the game they love.

malicious actors often repackage the same malicious code with different icons and names. All of them were also signed with the same certificate. A
quick check on the this certificate allowed me to identify other apps using the same code but a different package name, such as
“com.eset.ems2.gp”, which happens to be ESET’s official android app package name.
Our chosen sample also tries to impersonate Facebook Messenger by using a similar icon and the name “mssenger”.

[Page 4]
In addition to requesting Accessibility services, this malware is also capable of requesting DEVICE_ADMIN rights. The app contains the code for it,

Read keystrokes
Access file manager
Record audio
Send and receive SMS
Access contacts
Make calls
Harvest call logs

### 3.8 权限滥用 (**HIGH**)

Our chosen sample also tries to impersonate Facebook Messenger by using a similar icon and the name “mssenger”.

[Page 4]
In addition to requesting Accessibility services, this malware is also capable of requesting DEVICE_ADMIN rights. The app contains the code for it,
but when testing the malware we were surprised to see that it doesn’t actually request these rights during execution. Device admin rights can make
the application way more resilient by, for example, not allowing the user to delete it – which is why it’s very common to see malware request it at
start.

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.eset.ems2.gp` | 域名类型 |
| `yps.eton.application` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `0277b5385bcc033e01966990d356dc643814828e23c4a51be3bc7d1629545c5c` | 恶意文件 |
| `1876f72a33ac8b824e0f5e285d5d1addb4a640c0d7b51096eba05d38c3e2151e` | 恶意文件 |
| `1e181c65751d1c744d60f54871b93f186f1e1757c3970024340b33303b9e4ffe` | 恶意文件 |
| `59aa5297b983f2709a113eab96d1b1e18aa04029b1089ba0b3f23ed68f6659ab` | 恶意文件 |
| `5e9b28f53c008225f9e4174f4c2db6a03cd7e7fe77438d3f134bbd592e2d99e3` | 恶意文件 |
| `6930737f31cd792dc0c7e3830ac1e3cf575199527865f0b3dedfd810ad72e75c` | 恶意文件 |
| `727106140b81522f31bb534a9535438ec3442d1b0d6f551fe72aca3db999b060` | 恶意文件 |
| `7aa3ad9fc81681567d7ccbdbfb9203b0b054eabc341e4ec4d3cc0ff34ada9b01` | 恶意文件 |
| `d76e07060a3458cc69b5ab167b7cc86a6e872e5a51586c69315e723f916af965` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **勒索软件** (HIGH): 发现
4. **蠕虫传播** (HIGH): 发现
5. **权限滥用** (HIGH): 发现
