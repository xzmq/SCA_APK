# Android IOS Malware - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Android IOS Malware
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 日本, 俄罗斯, 伊朗, 越南
| 活动时间 | 未知
| 传播方式 | 钓鱼, 即时通讯软件传播
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
gbhackers.
Android IOS Malware
Hackers Compromise iOS &
Android Devices by
Dropping Malware Over
Hijacked WiFi Routers
ByBalaji April 4, 2019

[Page 2]
Cybercrimingals batthemaptincg tko ceomrprsom.ise iOS & Android devices via
advanced Phishing campaign that redirect iOS users to a malicious
landing page which allows attackers to collect sensitive information
and the Android users are compromised with malware via Hijacked
WiFi Routers.
Researchers believe that the attack belongs to Roaming Mantis
campaign that uses DNS hijacking attack to hack Android
smartphones, current attack car

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, account

automatically opens in a web browser and collected information
from the device will be sent to the attacker’s server.
Once users enter their credentials then it redirects to the next page,
which tried to steal the two-factor authentication code (PIN) sent to
the device.
P
h

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

that the following two features were updated as well to compromise
Android devices.:
Decryption algorithm for encrypted payload in Trojan-Dropper module
Stored destination and accounts for getting real C2
This new campaign affected many countries includes Russia, Japan,
India, Bangladesh, Kazakhstan, Azerbaijan, Iran and Vietnam
Also, researchers detected this malware over 6,800 times for over

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: twitter

compromised WiFi routers to overwrite DNS settings and discovered
that the following two features were updated as well to compromise
Android devices.:
Decryption algorithm for encrypted payload in Trojan-Dropper module
Stored destination and accounts for getting real C2
This new campaign affected many countries includes Russia, Japan,
India, Bangladesh, Kazakhstan, Azerbaijan, Iran and Vietnam

### 3.7 蠕虫传播 (**HIGH**)

Malicious APK Targets an
Android
Researchers discovered another malicious APK which is a variant of
sagawa.apk, a malware that was earlier distributed via SMS in Japan.
According to Kaspersky, We also found out that the threat actors had
compromised WiFi routers to overwrite DNS settings and discovered
that the following two features were updated as well to compromise

---

## 4. IoCs (威胁指标)

| **未发现可提取的 IoC 数据** | IoC 可能以图片表格形式存储于 PDF 中 |

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
| 传播性 | MEDIUM | 钓鱼, 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到4类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, account
2. **远程控制** (CRITICAL): config_update
3. **C2 反检测** (HIGH): twitter
4. **蠕虫传播** (HIGH): 发现
