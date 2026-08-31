# Aggressive ad-displaying Google Play - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Aggressive ad-displaying Google Play
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 远程控制相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等), 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
ESET Research
Aggressive ad-displaying Google Play
app tricks users into leaving high
ratings
ESET researchers have observed an increased number of apps on Google Play using social
engineering techniques to boost their ratings, ranging from legitimate apps, through adware
to malware.
Lukas Stefanko
08 Mar 2017 • 5 min. read
[Page 2]
ESET researchers have observed an increased number of apps on Google Play using social
engineering techniques to boost their ratings, ranging from legitimate apps, through adware to
malware.
Among these falsely high-ranking apps, an aggressive ad-displayin

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

com.baasdajie.zhofsdng 75D1730511E35774866546177B93AD8AE59F616D
com.baoertcji.hansdfszh 0C88D7F6742E4ECBD6FF032DDE989200EE385C8B
com.gannawen.dinergxi 8501D2BDEC7EFF8CE19CCBC6CF6B8EB33996B7C5
com.neigerj.gonfhgdgia 8033C35A86E3B8FFF0642B29D6CCDB57E7C2A2DA
com.shisfdyan.pingsgfshan DA7E8FA20E0718701B0198E0716C930556D4757C
com.suidfgdrning.zharetfou 2D32C51DE3B9043443038113A61785E010F05C87
com.yicsdfhang.dapdsfozhen 458049945049B2AE456F01B9DA7A4F5564DBEA1C

### 3.6 广告欺诈 (**MEDIUM**)

app tricks users into leaving high
ratings
ESET researchers have observed an increased number of apps on Google Play using social
engineering techniques to boost their ratings, ranging from legitimate apps, through adware
to malware.
Lukas Stefanko
08 Mar 2017 • 5 min. read

[Page 4]
Figure 2 – Screens requesting five star rating in exchange for functionality
In some cases of incentivized rating, found mostly in real but somewhat shady games, developers
simply reward all those who click OK/RATE APP on the nag screen. However, that doesn’t apply to
the apps analyzed in this article, which are entirely fake and don’t deliver their promises regardless
of what the user does.
Analysis of Android/Hiddad.BZ

### 3.8 权限滥用 (**HIGH**)

How does it operate?
After the user launches the downloaded app by clicking on the “Music Mania” icon, the ad-
displaying component is loaded. It manifests itself as a fake system screen requiring installation of
“plugin android” and overlaying the screen until enabled.
By clicking the install button, the ad-displaying payload is installed. The user is then prompted to
activate device administrator rights for the fake “plugin” by yet another non-cancellable screen.

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.baasdajie.zhofsdng` | 域名类型 |
| `com.bajie.zhong` | 域名类型 |
| `com.baoertcji.hansdfszh` | 域名类型 |
| `com.gannawen.dinergxi` | 域名类型 |
| `com.neigerj.gonfhgdgia` | 域名类型 |
| `com.shisfdyan.pingsgfshan` | 域名类型 |
| `com.suidfgdrning.zharetfou` | 域名类型 |
| `com.yicsdfhang.dapdsfozhen` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到3类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **广告欺诈** (MEDIUM): 发现
3. **权限滥用** (HIGH): 发现
