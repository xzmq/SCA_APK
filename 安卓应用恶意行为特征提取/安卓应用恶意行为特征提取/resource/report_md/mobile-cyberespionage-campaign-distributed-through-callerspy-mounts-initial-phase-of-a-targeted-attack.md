# By: Ecular Xu - 分析报告

> **来源**: Trend Micro
> **发布日期**: Dec 02, 2019
> **作者**: Ecular Xu
Dec
> **恶意软件名称**: By: Ecular Xu
> **厂商检测名**: `Trend Micro detects both`

---

## 1. 基本信息

| 字段 | 值 |
|------|------|
| 威胁类型 | 信息窃取相关
| 平台 | Android
| 目标地区 | 全球
| 活动时间 | 未知
| 传播方式 | 钓鱼
| 综合风险评级 | **CRITICAL**

---

## 2. 攻击链

[Page 1]
Malware
Mobile Campaign Start Targeted Attacks Using CallerSpy
We found a new spyware family hosted on a phishing website, and may initially be used for a targeted attack campaign. We first came across the threat in May via http://gooogle.press/
advertising a chat app called “Chatrious.”
By: Ecular Xu
Dec 02, 2019
Read time: ( words)
We found a new spyware family disguised as chat apps on a phishing website. We believe that
the apps, which exhibit many cyberespionage behaviors, are initially used for a targeted attack
campaign. We first came across the threat in May on the site http:/

---

## 3. 恶意行为描述

### 3.1 信息窃取 (**CRITICAL**)

**涉及技术**: sms, contacts, call_log

package (APK) file by clicking the download button indicated on the site.
The website became inactive for months after that encounter in May. We only noticed that it
came back in October, this time with a different app called “Apex App.” We have identified this as
a spyware family that can steal user’s personal information. Trend Micro detects both of the
threats as AndroidOS_CallerSpy.HRX.

[Page 2]

Collection Screen Capture T1513
the device
Standard Application Used Standard HTTP
Exfiltration T1437
Layer Protocol Protocol

[Page 13]

### 3.2 远程控制 (**CRITICAL**)

**涉及技术**: config_update

7cb0eb93de496e2141b6e0541465ca71a84063867381085692885c75aa59cb1b com.pdf.searcher.dd
Searcher
8ad18bd8f5d2f1fd9e00211170e8a540ddf7f51618588fab31b4ddd2b34b75e1 com.pdfd.researcher.resaq_ver1 Caller
c8e1a702a27309c22728792c64aad4abc14ec2bfad1b30a4f27b8ebc6bcc68ff com.sas.gservices.accesibility GSERVICES
C&C servers
3.95.71.123:3000

Figure 1. Screenshots of Chatrious (left) and Apex App (right)
Behavior analysis
CallerSpy claims it’s a chat app, but we found that it had no chat features at all and it was riddled
with espionage behaviors. When launched, CallerSpy initiates a connection with the C&C server
via Socket.IO to monitor upcoming commands. It then utilizes Evernote Android-Job to start
scheduling jobs to steal information.
Figure 2. CallerSpy initiates C&C connection (left) and then starts scheduling jobs (right)

Behavior analysis
CallerSpy claims it’s a chat app, but we found that it had no chat features at all and it was riddled
with espionage behaviors. When launched, CallerSpy initiates a connection with the C&C server
via Socket.IO to monitor upcoming commands. It then utilizes Evernote Android-Job to start
scheduling jobs to steal information.
Figure 2. CallerSpy initiates C&C connection (left) and then starts scheduling jobs (right)

[Page 13]
Used uncommon ports 2000,
Command and Control Uncommonly Used Port T1509
3000
Tags
Malware | APT & Targeted Attacks | Research | Mobile | Phishing

### 3.5 勒索软件 (**HIGH**)

threat actor may be waiting for a chance to spread the malware.
The malicious apps can be detected by Trend Micro solutions, such as the Trend Micro™ Mobile
Security for Android™. End users can also benefit from its multilayered security capabilities that
secure the device owner’s data and privacy and safeguard them from ransomware, fraudulent
websites, and identity theft.
For organizations, the Trend Micro Mobile Security for Enterprise suite provides device,
compliance, and application management, data protection, and configuration provisioning. It

### 3.6 广告欺诈 (**MEDIUM**)

the apps, which exhibit many cyberespionage behaviors, are initially used for a targeted attack
campaign. We first came across the threat in May on the site http://gooogle[.]press/, which was
advertising a chat app called “Chatrious.” Users can download the malicious Android application
package (APK) file by clicking the download button indicated on the site.
The website became inactive for months after that encounter in May. We only noticed that it
came back in October, this time with a different app called “Apex App.” We have identified this as
a spyware family that can steal user’s personal information. Trend Micro detects both of the

### 3.7 蠕虫传播 (**HIGH**)

[Page 10]
Figure 11. The app advertises to be available on different platforms
So far, our monitoring has not found any volume infection, which could mean that the
threat actor may be waiting for a chance to spread the malware.
The malicious apps can be detected by Trend Micro solutions, such as the Trend Micro™ Mobile
Security for Android™. End users can also benefit from its multilayered security capabilities that
secure the device owner’s data and privacy and safeguard them from ransomware, fraudulent

Figure 2. CallerSpy initiates C&C connection (left) and then starts scheduling jobs (right)

[Page 3]
CallerSpy sets several scheduling jobs to collect call logs, SMSs, contacts, and files on the device.
It also receives commands from the C&C server to take screenshots, which it later sends to the
server.
Figure 3. Scheduled jobs

---

## 4. IoCs (威胁指标)

### C2 服务器域名

| 域名 | 用途 |
|------|------|
| `18.206.105.66` | 域名类型 |
| `3.95.71.123` | 域名类型 |
| `40.114.109.69` | 域名类型 |
| `com.example.rat` | 域名类型 |
| `com.pdf.searcher.dd` | 域名类型 |
| `com.pdfd.researcher.resaq_ver1` | 域名类型 |
| `com.sas.gplayservices.accesibility` | 域名类型 |
| `com.sas.gservices.accesibility` | 域名类型 |

### IP 地址

| IP 地址 | 类型 |
|----------|------|
| `18.206.105.66` | 服务器 |
| `3.95.71.123` | 服务器 |
| `40.114.109.69` | 服务器 |
| `52.21.5.241` | 服务器 |

### 文件哈希 (SHA256)

| SHA256 | 备注 |
|--------|------|
| `0c4b08bec1251b1ebc715a7ef1a712cdcb4d37ce0093d88f7fa73b0e05bf7b0e` | 恶意文件 |
| `38acf26161a2c6429ee40d9b70d8419a9bd00eaa8740d221f943cea3229372dd` | 恶意文件 |
| `3bf85d0aff5ddc0c57e43b879631ee692d98d01f5c964336471f1cdfe0d291f8` | 恶意文件 |
| `7cb0eb93de496e2141b6e0541465ca71a84063867381085692885c75aa59cb1b` | 恶意文件 |
| `8ad18bd8f5d2f1fd9e00211170e8a540ddf7f51618588fab31b4ddd2b34b75e1` | 恶意文件 |
| `c8e1a702a27309c22728792c64aad4abc14ec2bfad1b30a4f27b8ebc6bcc68ff` | 恶意文件 |

---

## 5. 风险评估

| 维度 | 风险等级 | 依据 |
|------|----------|------|
| 信息窃取 | **CRITICAL** | 发现相关行为和描述 |
| 远程控制 | **CRITICAL** | 发现相关行为和描述 |
| 勒索软件 | **HIGH** | 发现相关行为和描述 |
| 广告欺诈 | **MEDIUM** | 发现相关行为和描述 |
| 蠕虫传播 | **HIGH** | 发现相关行为和描述 |
| 信息窃取 | CRITICAL | 检测到窃取行为 |
| 反检测能力 | HIGH | C2 隐藏和多通道通信 |
| 传播性 | MEDIUM | 钓鱼 |
| **综合风险** | **CRITICAL** | 检测到5类恶意行为 |

---

## 6. 关键结论速记

1. **信息窃取** (CRITICAL): sms, contacts, call_log
2. **远程控制** (CRITICAL): config_update
3. **勒索软件** (HIGH): 发现
4. **广告欺诈** (MEDIUM): 发现
5. **蠕虫传播** (HIGH): 发现
