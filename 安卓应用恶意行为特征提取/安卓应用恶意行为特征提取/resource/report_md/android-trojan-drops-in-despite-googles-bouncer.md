# Android trojan drops in, despite - 分析报告

> **来源**: 未知
> **发布日期**: 未知
> **作者**: 未知
> **恶意软件名称**: Android trojan drops in, despite
> **厂商检测名**: `未知`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 应用商店(Google Play等)
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
ESET Research
Android trojan drops in, despite
Google’s Bouncer
ESET recently discovered an interesting stealth attack on Android users, an app that is a
regular game but with an interesting addition: the application was bundled with another
application.
Lukas Stefanko
22 Sep 2015 • 7 min. read
[Page 2]
We at ESET recently discovered an interesting stealth attack on Android users, a fake app that is
trying to use a regular game's name but with one interesting addition: the application was bundled
with another application with the name systemdata or resourcea and that’s certainly a bit

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: contacts, account

ESET Research
Android trojan drops in, despite
Google’s Bouncer
ESET recently discovered an interesting stealth attack on Android users, an app that is a
regular game but with an interesting addition: the application was bundled with another
application.
Lukas Stefanko

### 3.2 远程控制 (**CRITICAL**)

maria com.tgame.maria ee8e4e3801c0101998b7dfee33f35f95 Android/TrojanDrop
journey
Google
Play com.appgp.main 195432955e70ec72018ead058f7abc2d Android/Mapin
Update
Zombies
highway com.absgame.zombiehighwaykiller 1516174c4a7f781c5f3ea6ac8447867b Android/TrojanDrop

functionality. It’s probably this delay that enabled the TrojanDownloader to get past Google’s
Bouncer malware prevention system.
After that, the Trojan requests device administrator rights and starts to communicate with its
remote C&C server. Android/Mapin contains multiple functionalities, such as pushing various
notifications, downloading, installing and launching applications, and obtaining the user’s private
information, but its main purpose appears to be to display fullscreen advertisements on the
infected device.

Communication through Google Cloud Messaging
The Trojan communicates with the server using Google Cloud Messaging ( GCM ). Such
communication is getting more and more common in malware these days. The backdoor can
respond to commands received from the server.

[Page 9]
Figure 8: Commands

ESET detects the games that install the Trojan as Android/TrojanDropper.Mapin and the Trojan itself
as Android/Mapin. According to our telemetry, Android users in India are currently the most affected,
with 73.58 percent of these detections observed.
It’s the backdoor Trojan that takes control of your device and makes it part of a botnet under the
attacker’s control. The Trojan sets timers that delay the execution of the malicious payload. This is
to make it less obvious that the trojanised game is responsible for the suspicious behavior. In some
variants of this infiltration, at least three days must elapse before the malware achieves full Trojan

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.absgame.zombiehighwaykiller` | 域名类型 |
| `com.appgp.main` | 域名类型 |
| `com.game.arrangeblock` | 域名类型 |
| `com.game.supermario` | 域名类型 |
| `com.popcap.pvz_row` | 域名类型 |
| `com.system.main` | 域名类型 |
| `com.tgame.candycrush` | 域名类型 |
| `com.tgame.maria` | 域名类型 |
| `com.tgame.plantvszombie` | 域名类型 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等) |
| **综合风险** | **CRITICAL** | 检测到2类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): contacts, account
2. **远程控制** (CRITICAL): 发现
