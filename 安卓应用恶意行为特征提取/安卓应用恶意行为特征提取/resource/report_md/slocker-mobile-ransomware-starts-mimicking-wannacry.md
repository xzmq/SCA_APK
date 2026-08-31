# A new variant of mobile ransomware SLocker was detected. It copies the GUI of th - 分析报告

> **来源**: Trend Micro
> **发布日期**: Jul 05, 2017
> **作者**: Ford Quin
Jul
> **恶意软件名称**: A new variant of mobile ransomware SLocker was detected. It copies the GUI of th
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
Ransomware
SLocker Mobile Ransomware Starts Mimicking WannaCry
A new variant of mobile ransomware SLocker was detected. It copies the GUI of the now-infamous WannaCry. It's one of the first Android file-encrypting ransomware, and the first
mobile ransomware to capitalize on the success of the WannaCry outbreak.
By: Ford Quin
Jul 05, 2017
Read time: 4 min (1139 words)
Updated July 6 3:00 AM CDT to clarify statement about Slocker variant being notable as an Android
file-encrypting ransomware.
Early last month, a new variant of mobile ransomware SLocker (detected by Trend Micro as
ANDROI

---

## 3. 恶意行为描述

### 3.2 远程控制 (**CRITICAL**)

SHA256 Package
Name
王者荣耀辅
200d8f98c326fc65f3a11dc5ff1951051c12991cc0996273eeb9b71b27bc294d com.android.tencent.zdevs.bah
助
2ffd539d462847bebcdff658a83f74ca7f039946bbc6c6247be2fc62dc0e4060 com.android.tencent.zdevs.bah 千变语⾳
王者荣耀前

### 3.3 银行木马 (**CRITICAL**)

Figure 6. Sample of encrypted file name
The ransomware presents victims with three options to pay the ransom, but in the sample we
analyzed, all three led to same QR code that asks the victims to pay via QQ (a popular Chinese
mobile payment service). If victims refuse to pay after three days, then the ransom price will be
raised. It threatens to delete all files after a week.

[Page 10]

### 3.4 C2 反检测 (**HIGH**)

**涉及技术**: forum

[Page 1]
Ransomware
SLocker Mobile Ransomware Starts Mimicking WannaCry
A new variant of mobile ransomware SLocker was detected. It copies the GUI of the now-infamous WannaCry. It's one of the first Android file-encrypting ransomware, and the first
mobile ransomware to capitalize on the success of the WannaCry outbreak.
By: Ford Quin
Jul 05, 2017

### 3.5 勒索软件 (**HIGH**)

[Page 1]
Ransomware
SLocker Mobile Ransomware Starts Mimicking WannaCry
A new variant of mobile ransomware SLocker was detected. It copies the GUI of the now-infamous WannaCry. It's one of the first Android file-encrypting ransomware, and the first
mobile ransomware to capitalize on the success of the WannaCry outbreak.

notable for being an Android file-encrypting ransomware, and the first mobile ransomware to
capitalize on the success of the previous WannaCry outbreak.

While this SLocker variant is notable for being able to encrypt files on mobile, it was quite short-
lived. Shortly after details about the ransomware surfaced, decrypt tools were published. And
before long, more variants were found. Five days after its initial detection, a suspect supposedly

### 3.6 广告欺诈 (**MEDIUM**)

Figure 7. Payment options for the ransomware

The ransomware tells victims that a decrypt key will be sent after the ransom has been paid.
Through our analysis, we found that if victims input the key and click the Decrypt button, the
ransomware will compare the key input with the value in MainActivity.m. But after tracking

[Page 11]

### 3.7 蠕虫传播 (**HIGH**)

[Page 2]
responsible for the ransomware was arrested by the Chinese police. Luckily, due to the limited
transmission channels (it was spread mostly through forums like QQ groups and Bulletin Board
Systems), the number of victims was very low.
Figure 1. Timeline for this ransomware sample
The original sample captured by Trend Micro was named “王者荣耀辅助” (King of Glory Auxiliary),

### 3.8 权限滥用 (**HIGH**)

requirements:
The lowercase paths for target files must not contain “/.”, “android”, “com.” and “miad”.

With the external storage as the root directory, target files should be in directories whose directory level is

smaller than 3 or the lowercase file paths contain “baidunetdisk”, “download” or “dcim”.
File name must contain “.” and the byte length of the encrypted file name should be less than 251

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `com.android.tencent.zdevs.bah` | 域名类型 |
| `com.android.tencent.zdevs.bah.MainActivity` | 域名类型 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `200d8f98c326fc65f3a11dc5ff1951051c12991cc0996273eeb9b71b27bc294d` | 恶意文件 |
| `2ffd539d462847bebcdff658a83f74ca7f039946bbc6c6247be2fc62dc0e4060` | 恶意文件 |
| `36f40d5a11d886a2280c57859cd5f22de2d78c87dcdb52ea601089745eeee494` | 恶意文件 |
| `c347e09b1489c5b8061828526f4ce778fda8ef7fb835255914eb3c9268a265bf` | 恶意文件 |
| `cb0a18bcc8a2c9a966d3f585771db8b2e627a7b4427a889191a93b3a1b261ba3` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 银行木马 | **CRITICAL** | 发现相关行为和描述 |
| C2 反检测 | **HIGH** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 权限滥用 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | HIGH | 未发现明确描述 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 应用商店(Google Play等), 即时通讯软件传播 |
| **综合风险** | **CRITICAL** | 检测到7类恶意行为 |

---

## 6. 关键结论速记

1. **远程控制** (CRITICAL): 发现
2. **银行木马** (CRITICAL): 发现
3. **C2 反检测** (HIGH): forum
4. **勒索软件** (HIGH): 发现
5. **广告欺诈** (MEDIUM): 发现
8. 其他行为见详细信息...
