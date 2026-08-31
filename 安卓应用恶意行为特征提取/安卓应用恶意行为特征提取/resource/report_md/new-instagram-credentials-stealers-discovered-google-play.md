# New Instagram credential stealers - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: ized attempt to log in on their behalf a
> **恶意软件名称**: New Instagram credential stealers
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 土耳其
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 钓鱼, 社交媒体传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
ESET Research
New Instagram credential stealers
discovered on Google Play
ESET researchers discovered 13 new Instagram credential stealers on Google play and looked
into the motivations behind their fraudulent schemes.
Lukas Stefanko
09 Mar 2017 • 4 min. read
[Page 2]
Instagram users have been the target of several new credential stealers, appearing on Google Play
as tools for either managing or boosting the number of Instagram followers.
[Page 3]
Figure 1 – The malicious apps on Google Play
Under the detection name Android/Spy.Inazigram, 13 malicious applications were discovered in t

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: contacts, account

[Page 1]
ESET Research
New Instagram credential stealers
discovered on Google Play
ESET researchers discovered 13 new Instagram credential stealers on Google play and looked
into the motivations behind their fraudulent schemes.

users worldwide. Altogether, the malicious apps have been installed by up to 1.5 million users. Upon
ESET’s notification, all 13 apps were removed from the store.
How do they operate?
All the applications employed the same technique of harvesting Instagram credentials and sending
them to a remote server. To lure users into downloading, the apps promised to rapidly increase the
number of followers, likes and comments on one’s Instagram account.
Ironically, the compromised accounts were used to raise follower counts of other users, as we

### 3.2 远程控制 (**CRITICAL**)

com.tr.nsgrfllowers 1,000 – 5,000 F32C674DBA78A748256991A7DBB2409FDA0CF302
com.tr.sdfgbvcderfdf 1,000 – 5,000 80E0A0704D256A0D4A02AD894A6206D93010E554
com.tr.yfASTngdYRl 500 – 1,000 91CE430EA41F04C38EEB150F5E96928A0448263F
com.tr.insfollowfreeinsta 500 – 1,000 D73F268D46DDD3213B82DC288428701EA09FB949
com.tkpcikahramani 500 – 1,000 B5AE6DBF283E0ABA19A896395F86C83808026D68
com.tr.aerfhasFYHDJGXMS 500 – 1,000 2D0AFB6B4BBB9C04BE826CA119CD6368A32A1289
com.tr.aedgcawwwSSSjkm 100 - 500 1757E843C80533C5DC7CF0699BB1D55147FFB349

### 3.7 蠕虫传播 (**HIGH**)

What happens to stolen credentials?
You might ask yourself: What use is there for a couple of (hundred thousand) stolen Instagram
credentials?
Apart from an opportunity to use compromised accounts for spreading spam and ads, there are
also various “business models” in which the most valuable assets are followers, likes and comments.
In our research, we’ve traced the servers to which the credentials are sent off and connected these
to websites selling various bundles of Instagram popularity boosters.

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.tr.aedgcawwwSSSjkm` | 域名类型 |
| `com.tr.aerfateharydar` | 域名类型 |
| `com.tr.aerfhasFYHDJGXMS` | 域名类型 |
| `com.tr.insfollowfreeinsta` | 域名类型 |
| `com.tr.instracker` | 域名类型 |
| `com.tr.nsgrfllowers` | 域名类型 |
| `com.tr.sdfgbvcderfdf` | 域名类型 |
| `com.tr.takdrfsfaewewe` | 域名类型 |
| `com.tr.yfASTngdYRl` | 域名类型 |
| `com.vavetech.superapp` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 钓鱼, 社交媒体传播 |
| **综合风险** | **CRITICAL** | 检测到3类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): contacts, account
2. **远程控制** (CRITICAL): 发现
3. **蠕虫传播** (HIGH): 发现
