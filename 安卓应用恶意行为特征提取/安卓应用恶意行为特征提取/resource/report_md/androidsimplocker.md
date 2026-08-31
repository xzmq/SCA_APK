# Android/Simplocker using FBI child- - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Android/Simplocker using FBI child-
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | C2 反检测相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 未知
| 综合风险评级 | **HIGH**

---

## 2. 攻击链

[Page 1]
ESET Research
Android/Simplocker using FBI child-
abuse warnings to scare victims into
paying $300
Last time we wrote about Android/Simplocker – the first ransomware for Android that
actually encrypts user files – we discussed different variants of the malware and various
distribution vectors that we’ve observed. Android/Simplocker has proven to be an actual
threat in-the-wild in spite of its weaknesses…
Robert Lipovsky
22 Jul 2014 • 2 min. read
[Page 2]
Last time we wrote about Android/Simplocker – the first ransomware for Android that actually
encrypts user files – we discussed diff

---

## 3. 恶意行为描述

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: forum

abuse warnings to scare victims into
paying $300
Last time we wrote about Android/Simplocker – the first ransomware for Android that
actually encrypts user files – we discussed different variants of the malware and various
distribution vectors that we’ve observed. Android/Simplocker has proven to be an actual
threat in-the-wild in spite of its weaknesses…
Robert Lipovsky

### 3.5 勒索软件 (**HIGH**)

Android/Simplocker using FBI child-
abuse warnings to scare victims into
paying $300
Last time we wrote about Android/Simplocker – the first ransomware for Android that
actually encrypts user files – we discussed different variants of the malware and various
distribution vectors that we’ve observed. Android/Simplocker has proven to be an actual
threat in-the-wild in spite of its weaknesses…

### 3.7 蠕虫传播 (**HIGH**)

[Page 5]
As usual, the trojan will use social engineering to trick the user into installing it – in the screenshot
to the left it’s masquerading as a Flash video player.
Our Android/Simplocker detection statistics until today don’t indicate the threat to be widespread
in English-speaking countries.
In case your files have been encrypted as a result of an Android/Simplocker infection, you can use
the updated ESET Simplocker Decryptor to restore them. But as always, we recommend

### 3.8 权限滥用 (**HIGH**)

12 years ago
Hi Scott. Anyone can install an application as Device Administrator - Android will display a message
as shown in the last screenshot in the post.
This is different from root.
0 0 Reply Share ›
−
scott flynn >lipovsky ⚑

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `download.eset.com` | 域名类型 |

### 恶意 URL

| URL | 类型 |
|-----|------|
| `http://download.eset.com/sp` | 钓鱼/下载 |
| `http://virusradar.com/en/to` | 钓鱼/下载 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 未知 |
| **综合风险** | **HIGH** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **C2 反检测** (HIGH): forum
2. **勒索软件** (HIGH): 发现
3. **蠕虫传播** (HIGH): 发现
4. **权限滥用** (HIGH): 发现
