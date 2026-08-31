# By: Lorin Wu - 分析报告

> **来源**: Trend Micro
> **发布日期**: Jan 03, 2018
> **作者**: Lorin Wu
Jan
> **恶意软件名称**: By: Lorin Wu
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
Mobile
Apps Bombard Users With Ads and Harvest Data
In early December, we found apps on Google Play exhibiting unwanted behavior. These apps posed as security tools and were actually able to perform utility tasks, but they also
secretly harvested user data, tracked user location, and pushed ads.
By: Lorin Wu
Jan 03, 2018
Read time: 4 min (1020 words)
In early December 2017, we found a total of 36 apps on Google Play that executed unwanted
behavior. These apps posed as useful security tools under the names Security Defender,
Security Keeper, Smart Security, Advanced Boost, and more. Th

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms

[Page 1]
Mobile
Apps Bombard Users With Ads and Harvest Data
In early December, we found apps on Google Play exhibiting unwanted behavior. These apps posed as security tools and were actually able to perform utility tasks, but they also
secretly harvested user data, tracked user location, and pushed ads.
By: Lorin Wu

### 3.6 广告欺诈 (**MEDIUM**)

appear. The aggressive ads show up during many different scenarios — for example, after the
app sends notices to unlock the device screen or if the user is told to connect to a charger. The
user is bombarded with ads with almost every action. It is clear that one of the main focuses of
the app is ad display and click fraud.
Users are actually asked to sign and agree to a EULA (end-user license agreement) which
describes the information that will be gathered and used by the app. But we can still say that the
app abuses privacy because the collection and transmission of personal data is unrelated to the

[Page 7]
Figure 4. The many notifications with fake data being pushed by this app
The developers of these apps go far to make their notifications believable. For an example, see
the figure below. If the user clicks the button to resolve the detected “Fraud SMS Broadcast
Vulnerability,” then the app will just show a simple animation illustrating that the problem has
been ‘resolved.’ This way, the user will think the app is working and will not be suspicious of it.

### 3.7 蠕虫传播 (**HIGH**)

[Page 7]
Figure 4. The many notifications with fake data being pushed by this app
The developers of these apps go far to make their notifications believable. For an example, see
the figure below. If the user clicks the button to resolve the detected “Fraud SMS Broadcast
Vulnerability,” then the app will just show a simple animation illustrating that the problem has
been ‘resolved.’ This way, the user will think the app is working and will not be suspicious of it.

### 3.8 权限滥用 (**HIGH**)

device, device specifics (like dots per inch and screen size), language, location information (from
the city the device is in to the longitude and latitude), and data on installed apps like Google Play
and Facebook. The app also notes what permissions are granted or not, specifically, usage stats,
accessibility, and read notification bar.
To secure mobile devices and protect valuable data, there are certain steps you can take. Here
are some tips:

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms
2. **广告欺诈** (MEDIUM): 发现
3. **蠕虫传播** (HIGH): 发现
4. **权限滥用** (HIGH): 发现
