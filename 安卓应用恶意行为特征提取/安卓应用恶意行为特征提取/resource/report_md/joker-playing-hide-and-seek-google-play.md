# Zscaler Blog - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: to bypass the Google Play
> **恶意软件名称**: Zscaler Blog
> **厂商检测名**: `未知`

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
Search ThreatLabz Customer Success Stories Careers Partners Support Contact Us Sign In English
Zscaler Blog
Get the latest Zscaler blog updates in your inbox Subscribe
Security Research
Joker Playing Hide-and-
Seek with Google Play
VIRAL GANDHI
September 24, 2020 - 7 min read
Joker is one of the most prominent malware families that continually targets Android devices. Despite
awareness of this particular malware, it keeps finding its way into Google’s official application market by
employing changes in its code, execution methods, or payload-retrieving techniques. This spyware is
desi

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log, account, device_info

Joker is one of the most prominent malware families that continually targets Android devices. Despite
awareness of this particular malware, it keeps finding its way into Google’s official application market by
employing changes in its code, execution methods, or payload-retrieving techniques. This spyware is
designed to steal SMS messages, contact lists, and device information along with silently signing up the
victim for premium wireless application protocol (WAP) services.
Our Zscaler ThreatLabZ research team has been constantly monitoring the Joker malware. Recently, we
have seen regular uploads of it onto the Google Play store. Once notified by us, the Google Android

The end payload also employs string obfuscation to hide all the important strings. It uses string
“nus106ba” to break all the important strings to hide it from simple string search.
Figure 16: The string obfuscation.
Figure 17 shows the SMS harvesting and WAP fraud done by Joker.

[Page 13]

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

IOCs
Infected Apps on GooglePlay:
MD5s Package Name
2086f0d40e611c25357e8906ebb10cd1 com.carefrendly.message.chat
b8dea8e30c9f8dc5d81a5c205ef6547b com.docscannercamscanpaper
5a5756e394d751fae29fada67d498db3 com.focusphoto.talent.editor
8dca20f649f4326fb4449e99f7823a85 com.language.translate.desire.voicetranlate

vetting process.
Scenario 1: Direct download
In some of the Joker variants, we saw the final payload delivered via a direct URL received from the
command and control (C&C) server. In this variant, the infected Google Play store app has the C&C
address hidden in the code itself with string obfuscation. We observed the string “sticker” was used to
break the C&C address to hide it from the simple grep or string search, as shown in Figure 1.
Figure 1: The C&C address string obfuscation.

vetting process.
Scenario 1: Direct download
In some of the Joker variants, we saw the final payload delivered via a direct URL received from the
command and control (C&C) server. In this variant, the infected Google Play store app has the C&C
address hidden in the code itself with string obfuscation. We observed the string “sticker” was used to
break the C&C address to hide it from the simple grep or string search, as shown in Figure 1.
Figure 1: The C&C address string obfuscation.

vetting process.
Scenario 1: Direct download
In some of the Joker variants, we saw the final payload delivered via a direct URL received from the
command and control (C&C) server. In this variant, the infected Google Play store app has the C&C
address hidden in the code itself with string obfuscation. We observed the string “sticker” was used to
break the C&C address to hide it from the simple grep or string search, as shown in Figure 1.
Figure 1: The C&C address string obfuscation.

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

[Page 6]
In some apps, we observed that for retrieving the final payload, the infected Google Play app uses a
stager payload. Here the infected Google Play store app has the stager payload URL encoded in the code
itself encrypted using Advanced Encryption Standard (AES). Upon infection, unlike scenario 1, it
downloads the stager payload rather than a final payload, as seen in Figure 4 and Figure 5.
We also saw two varieties of the stager payload—an Android Package (APK) or a Dalvik executable file.
Figure 4: The Dalvik executable stager payload download.

### 3.7 蠕虫传播 (**HIGH**)

Mint Leaf Message-Your Private Message
Unique Keyboard - Fancy Fonts & Free Emoticons
Tangram App Lock
Direct Messenger
Private SMS
One Sentence Translator - Multifunctional Translator
Style Photo Collage

Joker is one of the most prominent malware families that continually targets Android devices. Despite
awareness of this particular malware, it keeps finding its way into Google’s official application market by
employing changes in its code, execution methods, or payload-retrieving techniques. This spyware is
designed to steal SMS messages, contact lists, and device information along with silently signing up the
victim for premium wireless application protocol (WAP) services.
Our Zscaler ThreatLabZ research team has been constantly monitoring the Joker malware. Recently, we
have seen regular uploads of it onto the Google Play store. Once notified by us, the Google Android

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.carefrendly.message.chat` | 域名类型 |
| `com.focusphoto.talent.editor` | 域名类型 |
| `com.gooders.pdfscanner.gp` | 域名类型 |
| `com.language.translate.desire.voicetranlate` | 域名类型 |
| `com.nightsapp.translate.sentence` | 域名类型 |
| `com.password.quickly.applock` | 域名类型 |
| `com.powerful.phone.android.cleaner` | 域名类型 |
| `com.styles.simple.photocollage.photos` | 域名类型 |
| `com.unique.input.style.my.keyboard` | 域名类型 |
| `dirsms.welcome.android.dir.messenger` | 域名类型 |
| `message.standardsms.partmessenger` | 域名类型 |
| `mintleaf.message.messenger.tosms.ml` | 域名类型 |
| `omg.documents.blue.pdfscanner` | 域名类型 |
| `pdf.converter.image.scanner.files` | 域名类型 |
| `pdf.maker.scan.image.phone.scanner` | 域名类型 |
| `prisms.texting.messenger.coolsms` | 域名类型 |
| `www.anquanke.com` | 域名类型 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `https://twitter.com/ReBensk` | 钓鱼/下载 |
| `https://www.anquanke.com/post/id/211978` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): twitter
4. **蠕虫传播** (HIGH): 发现
