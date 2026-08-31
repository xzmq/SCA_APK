# 子Agent 02：代码与恶意行为分析（code_analysis / malicious_behavior / native_analysis）

本子文件由**主Agent**按需启动，负责解析输出特征JSON中以下三个顶级字段：

- `code_analysis`（代码分析）
- `malicious_behavior`（恶意行为检测）
- `native_analysis`（原生/底层代码分析）

**采用语言**：中文。**自包含**：大模型仅凭本文件即可完成这三个字段的特征提取，无需其它子文件。
**禁止 null**：任何字段的值都不允许为 `null`，只能使用下文给出的"默认空值"（数组 `[]`、对象 `{}`、字符串 `""`、数字 `0`、布尔 `false`）。

---

## 一、字段覆盖清单（本子文件负责）

| 顶级字段 | 子字段 | 类型 |
| --- | --- | --- |
| code_analysis | is_code_obfuscated | boolean |
| | obfuscation_techniques | array |
| | high_entropy_files_count | integer |
| | high_entropy_files | array（对象） |
| | dex_count | integer |
| | dex_files_list | array（string） |
| | has_dynamic_dex_loading | boolean |
| | weak_cryptographic_algorithms | array（string） |
| | sensitive_api_calls | array（对象） |
| | malicious_code_snippets | array（对象） |
| | webview_security_config | object |
| | has_embedded_payload | boolean |
| | embedded_payloads | array（对象） |
| | is_packed_and_repackaged | boolean |
| | anti_analysis | array（string） |
| | string_encryption | boolean |
| | related_native_libs_for_crypt | array（string） |
| malicious_behavior | sms_intercept_via_broadcast | boolean |
| | sms_intercept_via_content_observer | boolean |
| | dynamic_sms_receiver_registration | boolean |
| | boot_persistence | boolean |
| | service_keepalive | boolean |
| | c2_encrypted_urls | boolean |
| | cleartext_communication | boolean |
| | device_fingerprint_collection | boolean |
| | root_emulator_detection | boolean |
| | multi_process_architecture | boolean |
| | overlay_phishing | boolean |
| | ad_click_fraud | boolean |
| | notification_spam_or_phishing | boolean |
| | shell_command_execution | boolean |
| | admin_abuse_signal | boolean |
| | accessibility_abuse_signal | boolean |
| | has_c2_communication | boolean |
| | data_exfiltration | boolean |
| | sms_delete_capability | boolean |
| | call_forwarding | boolean |
| | dynamic_code_loading | boolean |
| | encryption_hardcoded_key | boolean |
| | suspicious_behavior_flags | array（对象） |
| | device_fingerprint_details | array（对象） |
| native_analysis | native_library_count | integer |
| | native_libraries | array（对象） |
| | executable_files | array（对象） |
| | native_abi_support | array（string） |
| | suspicious_native_libraries | array（对象） |

---

## 二、解析所需文件与工具

| 文件/资源 | 用途 | 工具 |
| --- | --- | --- |
| APK/DEX 字节码（.dex / .class） | 静态代码分析，恶意行为定位 | **jadx MCP（主）** / androguard（补充与失败替代） |
| `.so` 原生库（lib/ 目录） | 原生库统计与可疑判定 | python 脚本（解压 APK 后读取）+ jadx |
| APK 解压后的资源目录 | 熵值计算、payload 判定 | python 脚本 |
| AndroidManifest.xml | 交叉引用权限与组件（辅助） | jadx MCP / androguard |

**贯穿原则**：
1. **jadx MCP 是主要提取工具**，负责把 DEX 反编译为可读 Java 代码并检索类、方法、调用链。
2. **androguard 仅用于补充**（jadx 无法覆盖的原始字节层面信息）以及 **jadx MCP 提取失败后的替代选择**。
3. 本子文件中所有**涉及静态解析的环节都应使用 python 脚本代码实现**（写为可执行脚本，用于读取解包后的文件、计算熵值、统计库等）；所有**涉及动态/综合判断的环节交给大模型判断**（如是否"恶意"、是否"可疑"、行为归类）。

---

## 三、字段级解析

### 3.1 code_analysis.is_code_obfuscated（boolean）

- **类型**：boolean
- **解析目标**：判断应用代码是否经过混淆。
- **提取方法**：
  - 静态：python 脚本扫描反编译后的类名/方法名/字段名，统计是否出现大量 `a`、`b`、`c` 等无意义短名称，是否出现 `%`、`\u0000`、Unicode 转义、字符串被加密的艺术字符串。
  - 综合判断（交给大模型）：结合类名可读性、字符串可读性、是否使用 ProGuard/R8 产物特征，给出 `true/false`。
- **默认空值**：`false`

### 3.2 code_analysis.obfuscation_techniques（array，每项为对象）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| technique | string | 混淆技术名称 | 大模型综合判断后命名（如 `string_encryption`、`control_flow_obfuscation`、`class_renaming`、`native_library`、`dex_encryption`、`reflection`） | `""` |
| description | string | 该混淆技术的具体描述 | 大模型根据扫描到的代码特征用中文描述 | `""` |

- 检测技术线索（静态扫描）：字符串被 `encode`/`decrypt` 处理、存在大段反射（`Class.forName`、`getMethod`）、控制流被 `goto` 打乱、类名全部为单字母、存在 `pay`/`loadDex` 动态加载。
- **默认空值**：`[]`

### 3.3 code_analysis.high_entropy_files_count（integer）

- **类型**：integer
- **解析目标**：统计 APK 内熵值偏高（疑似加密/加壳/隐藏 payload）的文件数量。
- **提取方法**：python 脚本遍历 APK 内所有文件，计算 Shannon 熵。一般将熵值 > 7.0（8 位满熵）视为高熵。
- **默认空值**：`0`

### 3.4 code_analysis.high_entropy_files（array，每项为对象）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| path | string | 高熵文件的路径 | python 脚本记录文件名（如 `assets/enc.dat`、`lib/arm64-v8a/libxxx.so`） | `""` |
| entropy | number（浮点） | 该文件的熵值 | python 计算出的熵值，保留 2~3 位小数 | `0.0` |
| risk | string | 风险级别 | 大模型判断（`LOW`/`MEDIUM`/`HIGH`） | `""` |
| note | string | 补充说明 | 大模型中文描述该文件为何可疑（如“疑似加密的 DEX 壳”） | `""` |

- **默认空值**：`[]`

### 3.5 code_analysis.dex_count（integer）

- **类型**：integer
- **解析目标**：统计 APK 中 DEX 文件的数量。
- **提取方法**：python 脚本扫描 APK 内 `classes.dex`、`classes2.dex`、`classes3.dex`… 的实际数量。
- **默认空值**：`0`

### 3.6 code_analysis.dex_files_list（array，string）

- **类型**：array（string）
- **解析目标**：列出所有 DEX 文件路径。
- **提取方法**：python 脚本扫描结果填入（如 `["classes.dex","classes2.dex"]`）。
- **默认空值**：`[]`

### 3.7 code_analysis.has_dynamic_dex_loading（boolean）

- **类型**：boolean
- **解析目标**：是否存在运行时动态加载 DEX 的行为（加壳/热更新/恶意隐藏代码的常见特征）。
- **提取方法**：静态扫描是否调用 `DexClassLoader`、`PathClassLoader`、`dalvik.system.DexFile`、`loadDex`、`InMemoryDexClassLoader`、反射 `defineClass`。
- **默认空值**：`false`

### 3.8 code_analysis.weak_cryptographic_algorithms（array，string）

- **类型**：array（string）
  - 注意：字段名为 `weak_cryptographic_algorithms`（**algorithms**，复数）。
- **解析目标**：列出代码中使用的脆弱加密算法名。
- **提取方法**：静态扫描 `Cipher.getInstance(...)` 参数、`SecretKeySpec`、`MessageDigest` 中出现的算法字符串，识别 `DES`、`MD5`、`RC4`、`SHA1`、`ECB`、`3DES` 等弱算法。
- **默认空值**：`[]`

### 3.9 code_analysis.sensitive_api_calls（array，每项为对象）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| category | string | 敏感 API 的分类 | 大模型归入下列类目之一 | `""` |
| apis | array（string） | 该分类下命中的具体 API 全名 | 静态扫描结果 | `[]` |
| malicious_purpose | string | 这些 API 可能被用于的恶意用途 | 大模型结合上下文判断 | `""` |

- **常见敏感 API 分类与示例（供大模型归类参考）**：

| 分类 | 代表性 API（含包名/类名） | 潜在恶意用途 |
| --- | --- | --- |
| 短信收发 | `SmsManager.sendTextMessage`、`SmsManager.getDefault`、`ContentResolver.query`（uri `content://sms`）、`Telephony$Sms` | 拦截/发送/读取短信，扣费、短信拦截 |
| 通讯录/通话 | `ContactsContract`、`getContacts`、`CallLog`、`TelephonyManager.getCallState` | 窃取通讯录、通话记录 |
| 位置 | `LocationManager.getLastKnownLocation`、`requestLocationUpdates`、`getLatitude/getLongitude` | 追踪用户位置 |
| 文件/存储 | `Environment.getExternalStorageDirectory`、`File`/`FileInputStream` 读写、`getExternalFilesDir` | 窃取/篡改文件 |
| 网络/通信 | `URL.openConnection`、`HttpURLConnection`、`Socket`、`ProcessBuilder`、`Runtime.exec` | 数据外传、命令执行、C2 通信 |
| 系统/设备信息 | `TelephonyManager.getDeviceId`、`getSubscriberId`、`getImei`、`Build.*`、`Settings.Secure.getString` | 设备指纹采集 |
| 安装/执行 | `PackageManager.installPackage`、`ProcessBuilder`、`Runtime.exec`、`dalvik.system.*ClassLoader` | 提权、植入、动态加载 |
| 反射与动态 | `Class.forName`、`Method.invoke`、`DexClassLoader` | 隐藏恶意逻辑、逃避检测 |
| 加密 | `Cipher.getInstance("DES"...)`、`SecretKeySpec`、`MessageDigest` | 加密通信/加密 payload |

- **提取方法（基于 Axplorer 敏感 API 库精确匹配）**：
  1. 先用 python + openpyxl 读取 "……/resource/Axplorer汇总（增加api_level_26-36数据）.xlsx" 的 `Sheet`，得到敏感 API 全集（api 全名、type(sdk/framework)、permissions、permissions_level），建立匹配库。
  2. 用 **jadx MCP 反编译** 得到目标 APK 中所有方法签名，规范化为 `类路径.方法名(参数类型)返回类型` 格式，与 Excel 的 api 列精确比对（需处理 dex/jadx 返回签名与 excel 格式的差异，如参数/返回类型缩写与规范化）。
  3. 命中即记录该 API，`apis` 填入命中的 API 全名，并按 Excel 记 type、permissions；`permissions_level` 以 permission_mapping.json 为准（查不到记 normal）；`category` 由大模型基于 type/权限归类，`malicious_purpose` 由大模型判断。
  4. 无命中输出 `[]`。jadx 解析失败时可退化为 androguard 输出方法签名兜底。
  5. **工程实现说明**：jadx MCP 的 HTTP API 端点（见 `resource/jadx_mcp_api.txt`）提供 `get_all_classes`（列举全部类名）和 `get_methods_of_class`（按类列举方法），但**无"批量列举全部方法签名"端点**。因此实际实现采用混合策略：
     - **jadx MCP（主）**：调用 `get_all_classes` 获取应用类清单，过滤库类前缀，确定应用代码范围（遵守"jadx MCP 优先"原则）。
     - **androguard DEX（补充）**：批量解析 DEX 方法引用（method references），与 Axplorer Excel 精确比对。jadx MCP 无批量签名端点，androguard DEX 提供高效的批量签名提取能力。
     - 当 jadx MCP 不可用时，自动降级为 androguard-only 模式。
- **默认空值**：`[]`

### 3.10 code_analysis.malicious_code_snippets（array，每项为对象）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| class_name | string | 命中恶意代码的类名 | 静态定位 | `""` |
| method | string | 命中恶意代码的方法名 | 静态定位 | `""` |
| behavior | string | 该代码片段表现出的恶意行为描述 | 大模型中文概括 | `""` |
| code_snippet | string | 关键代码片段（截取） | 从反编译代码中粘贴关键行 | `""` |
| risk | string | 风险级别（`LOW`/`MEDIUM`/`HIGH`） | 大模型判断 | `""` |

- **【强制关联规则】**：`malicious_code_snippets` 有且只有与 `malicious_behavior` 字段中检测为 `true` 的恶意行为直接关联的代码，才能记录到该数组中。如果某恶意行为字段的值为 `false`/`[]`，则对应的代码片段**不记录**、**不搜索**。
- **提取顺序**：
  1. 先执行 `malicious_behavior`（3.18 ~ 3.20）的完整布尔检测，确定哪些行为字段为 `true`
  2. 遍历行为字段对应的代码检测模式（PatternMap），只对值为 `true` 的行为对应的模式进行搜索
  3. 搜索到的代码片段按上述表格字段填充，按风险等级排序后输出
- **输入依赖**：需接收 `malicious_behavior` 的完整检测结果 dict 作为输入。若输入为 `None`（独立运行/legacy mode），则回退为独立扫描所有模式（不区分 true/false）。
- **默认空值**：`[]`

### 3.11 code_analysis.webview_security_config（object）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| javascript_enabled | boolean | 是否启用 JavaScript | 静态扫描 `WebSettings.setJavaScriptEnabled(true)` | `false` |
| save_password_enabled | boolean | 是否允许保存密码 | 静态扫描 `setSavePassword(true)` | `false` |
| allow_file_access | boolean | 是否允许文件访问 | 静态扫描 `setAllowFileAccess(true)`、`setAllowUniversalAccessFromFileURLs` | `false` |
| loaded_urls | array（string） | WebView 加载的 URL 集合 | 静态扫描 `loadUrl(...)`/`loadData(...)` 参数 | `[]` |

- **默认空值**：`{}`（内部子字段按上述表格分别给空值）

### 3.12 code_analysis.has_embedded_payload（boolean）

- **类型**：boolean
- **解析目标**：APK 内是否嵌入了额外可执行/敏感 payload（如加密 DEX、ELF、动态加载文件）。
- **提取方法**：python 脚本检查 assets/ 中可疑文件、隐藏扩展名文件、高熵文件，结合 `.so` 字符串。
- **默认空值**：`false`

### 3.13 code_analysis.embedded_payloads（array，每项为对象）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| payload_type | string | payload 类型（如 `encrypted_dex`、`elf`、`apk`、`script`、`encrypted_file`） | 大模型判断 | `""` |
| path | string | payload 文件路径 | python 脚本记录 | `""` |
| purpose | string | 该 payload 的用途描述 | 大模型结合代码调用判断 | `""` |

- **默认空值**：`[]`

### 3.14 code_analysis.is_packed_and_repackaged（boolean）

- **类型**：boolean
- **解析目标**：是否经过加壳/二次打包。
- **提取方法**：检测特征——存在 `com.qihoo.util`、`com.shell.SuperApplication`、`DexClassLoader` 加载外部 dex、入口点被包装、lib/ 下有壳相关 `.so`。
- **默认空值**：`false`

### 3.14a code_analysis._packing_assessment（对象，内部字段）

> 由 `_assess_packing_risk()` 生成，综合 7 路信号评估加壳置信度。主 agent 在 Phase 4 从此字段填充 `file_basic.is_packed`（F-B）。

| 子字段 | 类型 | 说明 | 默认空值 |
| --- | --- | --- | --- |
| is_packed | boolean | confidence >= 40 时为 true | `false` |
| confidence | integer | 0-100 综合评分 | `0` |
| packer_name | string | 匹配到的加固方案名（来自 `packer_signatures.py` 15+ 壳特征库） | `""` |
| indicators | array | 触发的信号描述列表 | `[]` |
| dex_location | string | 加密 DEX 预期位置（通常 `assets/`） | `""` |
| matched_java_patterns | array | 匹配的 Java 包名/类名特征 | `[]` |
| matched_so_patterns | array | 匹配的 .so 库名特征 | `[]` |
| dex_count | integer | APK 中 DEX 文件数 | `0` |
| total_classes | integer | jadx MCP 获取的类总数（stub 判定依据） | `0` |

**7 路加权信号**：

| 信号 | 权重 | 说明 |
| --- | --- | --- |
| 已知壳特征匹配 (F-A) | 30 | `packer_signatures.py` 匹配 Java 包名 + .so 库名 |
| APK 整体熵 > 7.5 | 15 | 香农熵计算 |
| assets/ 下高熵文件 | 15 | 疑似加密 DEX |
| DexClassLoader 调用 | 15 | 壳加载器典型特征 |
| 单 DEX 但类数 < 50 | 10 | stub 加载器特征 |
| 壳相关 .so 库 | 10 | 可疑原生库名匹配 |
| 嵌入加密 payload | 5 | `has_embedded_payload` |

### 3.15 code_analysis.anti_analysis（array，string）

- **类型**：array（string）
- **解析目标**：列出反分析/反调试手段。
- **提取方法**：静态扫描是否调用 `Debug.isDebuggerConnected`、`System.getProperty("debuggable")`、`runtime.exec("su")`、`TracerPid` 读取、`kill` 自身检测进程、`Frida`/`Xposed` 检测、`isRooted` 检测。
- **默认空值**：`[]`

### 3.16 code_analysis.string_encryption（boolean）

- **类型**：boolean
- **解析目标**：字符串是否经过加密保护。
- **提取方法**：静态观察反编译代码中是否出现大量加密字符串（`\u0000`、base64）、自定义 `decrypt` 方法、`decode` 调用。
- **默认空值**：`false`

### 3.17 code_analysis.related_native_libs_for_crypt（array，string）

- **类型**：array（string）
- **解析目标**：与加密/加解密相关的原生库文件名列表。
- **提取方法**：结合 3.8 与 `System.loadLibrary(...)` 参数，列出参与加密的 `.so` 名称（如 `libencrypt.so`）。
- **默认空值**：`[]`

---

### 3.18 malicious_behavior：各布尔标志

以下布尔字段按相同方法检测（静态扫描命中相关 API 模式，交由大模型结合上下文判定 `true/false`），逐个列出：

| 子字段 | 类型 | 解析目标 | 主要检测 API/线索 | 默认空值 |
| --- | --- | --- | --- | --- |
| sms_intercept_via_broadcast | boolean | 是否通过广播接收器拦截短信 | 注册 `android.provider.Telephony.SMS_RECEIVED` 广播、`BroadcastReceiver.onReceive` 里读取短信 | `false` |
| sms_intercept_via_content_observer | boolean | 是否通过 ContentObserver 监控短信数据库 | `ContentResolver.registerContentObserver`（uri `content://sms`）、`getContentObserver` | `false` |
| dynamic_sms_receiver_registration | boolean | 是否动态注册短信接收器 | `registerReceiver` + SMS 相关 action，且非清单静态声明 | `false` |
| boot_persistence | boolean | 是否开机自启持久化 | 监听 `BOOT_COMPLETED` 广播、`RECEIVE_BOOT_COMPLETED` 权限 | `false` |
| service_keepalive | boolean | 是否有服务保活机制 | `startForegroundService`、`START_STICKY`、双进程守护、`AlarmManager` 定时重启 | `false` |
| c2_encrypted_urls | boolean | C2 地址是否加密存储 | 代码中出现 DES/base64 解密后拼接 URL（参见 c2 分析） | `false` |
| cleartext_communication | boolean | 是否明文通信 | 见子03 `has_c2`/`cleartext_traffic_permitted` 交叉判断 | `false` |
| device_fingerprint_collection | boolean | 是否采集设备指纹 | 命中 3.9 中"系统/设备信息"类 API | `false` |
| root_emulator_detection | boolean | 是否探测 root/模拟器 | `su` 检测、`Build.FINGERPRINT`、`isEmulator`、`google_sdk`、`Magic` 路径检测 | `false` |
| multi_process_architecture | boolean | 是否多进程架构 | `android:process` 属性、`Process.myPid`、多进程保活 | `false` |
| overlay_phishing | boolean | 是否使用悬浮窗/覆盖层钓鱼 | `TYPE_APPLICATION_OVERLAY`、`WindowManager.addView`、`FLAG_OVERLAY`、`SYSTEM_ALERT_WINDOW` 权限 | `false` |
| ad_click_fraud | boolean | 是否模拟点击/广告欺诈 | 后台 `dispatchTouchEvent`、`performClick`、频繁 `WebView` 广告点击 | `false` |
| notification_spam_or_phishing | boolean | 是否通知栏垃圾推送/仿冒通知 | `NotificationManager.notify` 大量调用、伪装系统通知 | `false` |
| shell_command_execution | boolean | 是否执行 shell 命令 | `Runtime.getRuntime().exec`、`ProcessBuilder`、`/system/bin/sh` | `false` |
| admin_abuse_signal | boolean | 是否滥用设备管理器 | `DeviceAdminReceiver`、`ACTION_ADD_DEVICE_ADMIN`、`BIND_DEVICE_ADMIN` | `false` |
| accessibility_abuse_signal | boolean | 是否滥用无障碍服务 | `AccessibilityService`、`BIND_ACCESSIBILITY_SERVICE`（高危，可读取全屏/模拟点击） | `false` |
| has_c2_communication | boolean | 是否存在C2远程控制通信 | 硬编码URL + `HttpURLConnection`/`Socket` + 数据上传 | `false` |
| data_exfiltration | boolean | 是否存在数据外传 | 设备指纹采集 + `getBytes`/`POST`/`OutputStream` 上传路径 | `false` |
| sms_delete_capability | boolean | 是否具备短信删除能力 | `ContentResolver.delete` + `content://sms` | `false` |
| call_forwarding | boolean | 是否设置呼叫转移 | `setCallForward`、`CF_ENABLE`、`GSM_CALL_FORWARD` | `false` |
| dynamic_code_loading | boolean | 是否动态加载DEX | `DexClassLoader`、`PathClassLoader`、`loadDex` | `false` |
| encryption_hardcoded_key | boolean | 是否使用硬编码密钥加密 | `Cipher.getInstance("DES")` + `SecretKeySpec` 硬编码key | `false` |

> **注意区分**：`code_analysis.has_dynamic_dex_loading`（3.7）与 `malicious_behavior.dynamic_code_loading` 虽然都涉及 DexClassLoader，但含义不同：
> - `code_analysis.has_dynamic_dex_loading`：代码中是否出现 DexClassLoader 等动态加载调用（技术事实）
> - `malicious_behavior.dynamic_code_loading`：DexClassLoader 是否被用于恶意目的如隐藏载荷或逃避检测（行为判定）

- **交集说明**：`sms_intercept_via_broadcast` 与 `sms_intercept_via_content_observer` 为**恶意短信拦截的关键信号**，命中时应重点标记。

### 3.19 malicious_behavior.suspicious_behavior_flags（array，每项为对象）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| behavior | string | 可疑行为名称 | 从 3.18 归类命名 | `""` |
| detected | boolean | 是否被检测到 | 有证据则为 `true` | `false` |
| risk | string | 风险级别 | 大模型判断（`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`） | `""` |
| priority_from_report | boolean | 是否来自报告优先检测 | 匹配 Excel 报告确认为 true | `false` |
| report_confirmed | boolean | 是否被安全报告确认 | 报告 MD 中有该行为描述为 true | `false` |

- **默认空值**：`[]`

### 3.20 malicious_behavior.device_fingerprint_details（array，每项为对象）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| field_name | string | 采集的指纹字段名 | 静态识别（如 `IMEI`、`IMSI`、`ANDROID_ID`、`MAC`、`serial`） | `""` |
| collection_method | string | 采集方法 | 大模型描述引用的 API/代码路径 | `""` |
| transmitted | boolean | 该指纹是否被上传/外传 | 结合网络外传调用判断 | `false` |

- **默认空值**：`[]`

---

### 3.21 native_analysis.native_library_count（integer）

- **类型**：integer
- **解析目标**：统计原生库（`.so`）数量。
- **提取方法**：python 脚本遍历 `lib/` 各 ABI 目录，统计 `.so` 文件数（同库多 ABI 可只计一次或计数，需保持一致并在 note 中说明）。
- **默认空值**：`0`

### 3.22 native_analysis.native_libraries（array，每项为对象）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| path | string | .so 文件路径 | python 脚本记录 | `""` |
| abi | string | 支持的 ABI | 解析路径目录名（`armeabi-v7a`、`arm64-v8a`、`x86`、`x86_64`） | `""` |
| size_bytes | integer | 文件大小（字节） | python 脚本读取 | `0` |
| entropy | number | 文件熵值 | python 计算 | `0.0` |
| is_standard_library | boolean | 是否为系统标准库 | 大模型对比已知系统库名判断 | `false` |
| is_suspicious | boolean | 是否可疑 | 大模型结合名称/熵/代码引用判断 | `false` |
| note | string | 补充说明 | 中文描述（如“非标准库，疑似加密逻辑”） | `""` |

- **默认空值**：`[]`

### 3.23 native_analysis.executable_files（array，每项为对象）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| path | string | 可执行文件路径（ELF/二进制） | python 脚本扫描 | `""` |
| abi | string | 平台 | 解析 | `""` |
| risk_level | string | 风险级别 | 大模型判断 | `""` |
| note | string | 补充 | 中文描述 | `""` |

- **默认空值**：`[]`

### 3.24 native_analysis.native_abi_support（array，string）

- **类型**：array（string）
- **解析目标**：列出应用支持的 ABI。
- **提取方法**：汇总 `lib/` 目录名（如 `["arm64-v8a","armeabi-v7a"]`）。
- **默认空值**：`[]`

### 3.25 native_analysis.suspicious_native_libraries（array，每项为对象）

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| library_name | string | 可疑库名 | 大模型从 native_libraries 中筛选 | `""` |
| abi | string | 平台 | 记录 | `""` |
| suspicious_reason | string | 可疑原因 | 大模型中文描述（如“库名无意义、高熵、被代码加载执行”） | `""` |

- **默认空值**：`[]`

---

### 3.26 report-driven 检测增强（可选）

当 `run_pipeline.py` 通过 `report_apk_mappings_new.xlsx` 查询到匹配的报告 MD 文件时，本子 agent 会额外获得以下输入：

- **`known_behaviors`**：报告 `## 3. 恶意行为描述` 下提取的行为列表 `[{"name": "...", "risk": "..."}, ...]`
- **`behavior_keywords`**：报告 `**涉及技术**: xxx` 行中解析出的技术关键词列表 `["keyword1", "keyword2", ...]`

**增强规则**：

1. **行为名 → 模板字段映射**：使用 `common.map_report_behavior_to_template_field()` 将报告行为名映射到 `malicious_behavior` 的字段名（见下表）
2. **关键词扩展搜索**：对报告中确认的行为，将该行为的标准检测 patterns 与报告的 `behavior_keywords` 合并后作为扩展搜索词集
3. **优先级标记**：在 `suspicious_behavior_flags` 数组中，对映射到的行为项增加 `report_confirmed: true` 标记
4. **报告覆盖静态未检测**：即使静态检测未命中(false)，但报告确认的行为，仍以 `report_confirmed: true` + `static_detected: false` 标记输出，供分析者参考

**行为名 → 模板字段映射表（报告名 → malicious_behavior 字段）**：

| 报告行为名（关键词匹配） | malicious_behavior 字段 |
| --- | --- |
| "远程控制" / "C2通信" | `has_c2_communication` |
| "C2反检测" | `c2_encrypted_urls` |
| "短信劫持" / "短信窃取" | `sms_intercept_via_content_observer` |
| "短信拦截" | `sms_intercept_via_broadcast` |
| "隐私窃取" / "设备信息采集" / "信息窃取" | `device_fingerprint_collection` |
| "加密混淆" / "加密" | `encryption_hardcoded_key` |
| "持久化驻留" / "保活" | `service_keepalive` |
| "Root" / "模拟器对抗" / "反检测" | `root_emulator_detection` |
| "钓鱼" / "覆盖攻击" / "overlay" | `overlay_phishing` |
| "设备管理" / "系统破坏" | `admin_abuse_signal` |
| "数据外传" / "网络泄露" / "数据泄露" | `data_exfiltration` |
| "广告欺诈" | `ad_click_fraud` |
| "银行木马" | `sms_intercept_via_broadcast` |
| "蠕虫传播" | `sms_delete_capability` |
| "呼叫转移" | `call_forwarding` |

- **默认空值**：无报告时所有增强规则跳过，回退为标准静态检测流程

---

## 四、全局约束（本子文件）

1. **绝对禁止 null**：所有数组字段填 `[]`、对象字段填 `{}`、字符串填 `""`、数字填 `0`、布尔填 `false`；嵌套子字段同样遵守。
2. **工具主次**：jadx MCP 反编译与检索为主；androguard 仅补充字节层面信息和 jadx 失败时替代。
3. **静态 vs 动态**：一切机械性、可脚本化的静态解析（文件遍历、熵值、库统计、关键词粗筛）都用 python 脚本实现；一切需语义判断的结果（是否恶意、风险级别、行为命名、用途描述）**交由大模型综合判断**。
4. **与其它子文件一致**：编码/加密结论与子03（c2）交叉引用；`cleartext_communication` 与子03 `cleartext_traffic_permitted` 保持一致。
5. **可追溯**：对每个命中结果，尽量记录来源类/方法，便于主 Agent 汇总校验。
6. **执行顺序约束**：`malicious_behavior`（3.18~3.20）必须在 `code_analysis.malicious_code_snippets`（3.10）之前执行，因为代码片段提取依赖行为布尔检测结果。
7. **报告驱动检测**：当 `run_pipeline.py` 通过 Excel 匹配到报告 MD 文件并解析出 `known_behaviors`/`behavior_keywords` 后，本子 agent 应按 3.26 规则进行关键词扩展搜索和优先级标记。
