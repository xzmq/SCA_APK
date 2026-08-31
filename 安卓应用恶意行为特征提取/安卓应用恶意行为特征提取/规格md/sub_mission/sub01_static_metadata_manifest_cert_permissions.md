# 子01 静态元数据 — Manifest 与证书/权限提取规格

> 本文件由**主 Agent** 启动的**子 Agent 01** 执行。仅凭本文即可完成对应字段的提取，无需接触模板 JSON。
> 输入：一只安卓 APK 文件的绝对路径；输出：本文所列全部字段对应的 JSON。
> **全局铁律（贯穿所有子文件，务必遵守）**：
> - **不允许出现 `null`**。数组为空用 `[]`；对象为空用 `{}`；字符串为空用 `""`；数字为 0；布尔为 `false`。
> - 主要提取工具为 **jadx MCP**；**androguard** 仅用于补充、以及在 jadx MCP 提取失败时的替代选择。优先尝试 jadx MCP，失败再退回 androguard。
> - **读取 APK 结构、AndroidManifest.xml、证书、资源用 python 脚本**；**DEX 与代码层面的反编译检索、调用点定位、行为判定统一用 jadx MCP 反编译实现，不采用裸字节码扫描**；**所有动态/综合判断（这个字段“像不像”恶意、风险高低）交给大模型判断**。
> - 所有路径、字符串字段如无法解析出值，一律写默认空值，绝不写 `null`。

---

## 一、本子文件负责的顶级字段（覆盖清单）

本子文件解析以下顶级字段（完整提取所有子字段）：

1. `file_basic` —— 文件基础信息与包信息
2. `certificate_analysis` —— 签名证书分析
3. `permissions` —— 权限分析
4. `components` —— 四大组件（Activity/Service/Receiver/Provider）可疑性分析

---

## 二、解析所需文件/资源

| 资源 | 用途 | 提取方式 |
|---|---|---|
| APK 整体文件 | SHA256/MD5/SHA1、文件大小、文件熵 | python（读取字节） |
| `META-INF/*.RSA` 或 `*.DSA`/`*.EC`（`META-INF/` 下签名文件） | 证书解析 | python（证书 DER 解析） |
| `AndroidManifest.xml` | 包名、版本、SDK、权限、四大组件、feature、allowCleartextTraffic、isMainEntry/exported 等 | jadx MCP 读取 /与 androguard 互补 |
| 解码后的 `res/` 与 `resources.arsc` | appLabel 应用名称 | jadx MCP / androguard |
| `classes*.dex`（DEX 字节码） | 判断组件是否为入口、是否有动态注册逻辑（配合子02） | jadx MCP（反编译为 smali/java） |

> 说明：`components` 中部分判断（is_main_entry、is_hidden、has_dynamic_code_loading 等）需要结合 jadx MCP 反编译出的源码，属于静态解析，仍由 python/jadx 完成；涉及"该组件为何可疑"的主观综合描述（suspicion_reason）由大模型生成。

---

## 三、字段级解析（逐字段：目标 / 方法 / 默认空值）

### 3.1 `file_basic`（对象）

> 对象默认空值：`{ "sha256":"", "md5":"", "sha1":"", "file_size_bytes":0, "file_entropy":0, ... }`

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `sha256` | string | 整个 APK 文件的 SHA-256 十六进制摘要 | python 读取 APK 文件字节计算 SHA-256 | `""` |
| `md5` | string | APK 文件 MD5 摘要 | python 计算 MD5 | `""` |
| `sha1` | string | APK 文件 SHA-1 摘要 | python 计算 SHA-1 | `""` |
| `file_size_bytes` | integer | APK 文件大小（字节） | python `os.path.getsize` 或 `stat` | `0` |
| `file_entropy` | number | 整个 APK 字节熵值，范围 0~8 | python 基于 256 字节频次算香农熵；**阈值：>7.5 视为高熵（可能加壳/加密）** | `0` |
| `package_name` | string | 应用包名，对应 Manifest `manifest/@package` 或 `application` 命名空间 | jadx MCP 读 AndroidManifest.xml；androguard `get_package()` 备选 | `""` |
| `package_name_entropy` | number | 包名字符串熵值 | 对 `package_name` 字符串算香农熵；**阈值：>3.0 视为随机化包名（恶意信号）** | `0` |
| `app_label` | string | 应用显示名称，Manifest `application/@android:label`（可能引用 res 字符串） | jadx MCP 读 manifest + 资源字符串；androguard 备选 | `""` |
| `version_code` | integer | 版本号整数，Manifest `manifest/@android:versionCode` | jadx MCP / androguard | `0` |
| `version_name` | string | 版本名，`manifest/@android:versionName` | jadx MCP / androguard | `""` |
| `min_sdk_version` | integer | 最低支持系统版本，`uses-sdk/@android:minSdkVersion` | jadx MCP / androguard `get_min_sdk_version()` | `0` |
| `target_sdk_version` | integer | 目标系统版本，`uses-sdk/@android:targetSdkVersion` | jadx MCP / androguard `get_target_sdk_version()` | `0` |
| `is_packed` | boolean | 是否疑似加壳 | 由主 agent 在 Phase 4 合并阶段从 `code_analysis._packing_assessment` 读取（F-B 填充，非子01 直接计算）。`_packing_assessment` 由子02 的 `_assess_packing_risk()` 生成（7 路信号综合评分） | `false` |
| `malware_family` | string | 若已识别恶意家族则填家族名；否则 `""` | **获取优先级**：① 主流程 `run_pipeline.py` 通过 `common.load_apk_report_mapping()` 查询 `report_apk_mappings_new.xlsx`，按 APK sha256 匹配 `report_file` 列得到报告文件名(带.pdf后缀)，再从同文件的 `malware_family` 列获取家族名（**首选**）；② 旧 `malware_family.xlsx` 的 `{sha256: report_family}` dict 作为兜底 fallback。Excel 路径：`resource/report_apk_mappings_new.xlsx` | `""` |

### 3.2 `certificate_analysis`（对象）

> 对象默认空值示例：`{ "is_self_signed":false, "is_debug_certificate":false, "signing_algorithm":"", ... , "signer_certificates":[] }`

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `is_self_signed` | boolean | Subject（主体）是否等于 Issuer（颁发者） | 解析证书两字段比对，完全相同为 true | `false` |
| `is_debug_certificate` | boolean | 是否 Android 调试证书（CN 通常为 "Android Debug"） | 检查 Subject CN 是否含 "Android" 且常见调试特征 | `false` |
| `signing_algorithm` | string | 签名算法名，如 "SHA256withRSA" / "SHA1withRSA" | python 读取证书 Signature Algorithm 字段 | `""` |
| `public_key_type` | string | 公钥算法类型，如 "RSA"/"EC"/"DSA" | python 读 SubjectPublicKeyInfo 算法标识 | `""` |
| `public_key_bit_length` | integer | 公钥模长/位数，RSA 即模数位长 | python 计算 | `0` |
| `subject` | string | 证书主体可识别名（完整的 DN 字符串） | python 读证书 Subject X500Name | `""` |
| `issuer` | string | 证书颁发者 DN | python 读证书 Issuer X500Name | `""` |
| `subject_common_name` | string | Subject 的 CN（Common Name） | python 从 Subject 中取 CN | `""` |
| `subject_organization` | string | Subject 的 O（Organization）字段 | python 从 Subject 中取 O | `""` |
| `subject_country` | string | Subject 的 C（Country）字段 | python 从 Subject 中取 C | `""` |
| `valid_from` | string | 证书生效时间（ISO 字符串） | python 读 notBefore | `""` |
| `valid_until` | string | 证书失效时间（ISO 字符串） | python 读 notAfter | `""` |
| `valid_days` | integer | 证书有效天数（notAfter − notBefore 的天数） | python 计算 | `0` |
| `public_key_hash` | string | **仅公钥部分**的 SHA-256 摘要（十六进制，含分隔冒号或不含均可） | python 对 SubjectPublicKeyInfo 的位串做 SHA-256 | `""` |
| `fingerprint_sha256` | string | 证书整体（DER）的 SHA-256 指纹 | python 对证书 DER 编码做 SHA-256 | `""` |
| `fingerprint_sha1` | string | 证书整体（DER）的 SHA-1 指纹 | python 对证书 DER 编码做 SHA-1 | `""` |
| `subject_anomaly` | boolean | Subject 信息是否异常（CN/O 为空、明显伪造、随机字符串等） | 大模型判断 | `false` |
| `signer_certificates` | array | 签名者证书链列表（多证书暗示重新打包/多签名） | python 解析 apk 签名块中多证书 | `[]` |

`signer_certificates` 数组每项为对象，字段：

| 子字段 | 类型 | 提取方法 | 默认空值 |
|---|---|---|---|
| `serial_number` | string | 证书序列号（十六进制） | `""` |
| `subject_cn` | string | 该项证书 Subject 的 CN | `""` |
| `issuer_cn` | string | 该项证书 Issuer 的 CN | `""` |

### 3.3 `permissions`（对象）

> 对象默认空值示例：`{ "total_perm_count":0, "dangerous_perm_count":0, "all_permissions":[], "malicious_perm_combos":[], "high_signal_permissions":[], "custom_permissions":[], "uses_features":[] }`

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `total_perm_count` | integer | Manifest 声明的权限总数 | jadx MCP / androguard 统计 `uses-permission` | `0` |
| `dangerous_perm_count` | integer | 其中危险级别权限数量（protectionLevel 为 dangerous 或 runtime） | python 以 resource/permission_mapping.json 判定（查不到的不计入；level strip 后含 'dangerous' 才计入） | `0` |
| `all_permissions` | array | 全部权限详情列表 | jadx MCP / androguard 枚举权限 | `[]` |
| `malicious_perm_combos` | array | 已知恶意权限组合是否被触发 | python 判断组合内权限是否齐全，详见下表 | `[]` |
| `high_signal_permissions` | array | 高危敏感权限明细 | python 对照高危权限名单（见下表） | `[]` |
| `custom_permissions` | array | 应用自定义的权限声明（`<permission>` 标签） | jadx MCP / androguard | `[]` |
| `uses_features` | array | 声明的硬件/软件 feature（`uses-feature`） | jadx MCP / androguard | `[]` |

`all_permissions` 数组每项对象：

| 子字段 | 类型 | 提取方法 | 默认空值 |
|---|---|---|---|
| `name` | string | 权限名（如 `android.permission.RECEIVE_SMS`） | `""` |
| `protection_level` | string | python 查询 resource/permission_mapping.json 中该权限的 permissions_level（键=权限全名），查到则按该级值填写（如有 `|` 分隔保留原样），查不到一律记 `normal` | `""` |
| `is_dangerous` | boolean | python 取 permission_mapping.json 中该权限的 level，level.strip() 含子串 `dangerous` 则为 true，查不到记 false | `false` |

`malicious_perm_combos` 数组每项对象：

| 子字段 | 类型 | 提取方法 | 默认空值 |
|---|---|---|---|
| `attack_type` | string | 攻击类型名（见下表 attack_type） | `""` |
| `required_perms` | array of string | 该攻击类型要求的权限名列表（照抄下表） | `[]` |
| `is_triggered` | boolean | 是否所有 required_perms 都出现在声明权限中 | python 集合判断 | `false` |
| `risk_level` | string | 风险等级（CRITICAL/HIGH/MEDIUM） | 照抄下表 | `""` |
| `description` | string | 该组合的恶意行为中文描述 | 大模型生成 | `""` |

**恶意权限组合判定表（attack_type → required_perms → risk_level）：**

| attack_type | required_perms | risk_level |
|---|---|---|
| 短信窃取/拦截 | `[RECEIVE_SMS, READ_SMS, INTERNET]` | CRITICAL |
| 设备信息窃取 | `[READ_PHONE_STATE, INTERNET]` | HIGH |
| 静默后台驻留 | `[RECEIVE_BOOT_COMPLETED, WAKE_LOCK]` | MEDIUM |
| 修改系统设置 | `[WRITE_SETTINGS]` | HIGH |
| 悬浮窗覆盖 | `[SYSTEM_ALERT_WINDOW]` | CRITICAL |
| 隐私数据窃取 | `[READ_CONTACTS, INTERNET]` | HIGH |
| 文件窃取 | `[WRITE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE, INTERNET]` | MEDIUM |

> 判定规则：逐个组合检查——若该组合 `required_perms` **全部都**出现在应用声明的权限集合中，则 `is_triggered=true`，写入该组合对象；否则 `is_triggered=false` 仍写入（保持字段数量稳定）。每个粗暴组合都作为一项。

`high_signal_permissions` 数组每项对象：

| 子字段 | 类型 | 提取方法 | 默认空值 |
|---|---|---|---|
| `name` | string | 权限名 | `""` |
| `protection_level` | string | 保护级别 | `""` |
| `is_dangerous` | boolean | 是否危险级别 | `false` |
| `malicious_usage` | string | 该权限可用于的恶意活动中文描述（大模型） | `""` |
| `malicious_signal` | boolean | 是否判定为恶意信号（对照高危名单命中即 true） | `false` |

> **高危权限名单**（命中其中任一项即写入 `high_signal_permissions` 且 `malicious_signal=true`）：
> `RECEIVE_SMS`、`READ_SMS`、`READ_PHONE_STATE`、`SEND_SMS`、`READ_CONTACTS`、`WRITE_EXTERNAL_STORAGE`、
> `BIND_ACCESSIBILITY_SERVICE`（此权限 protection_level 以 permission_mapping.json 为准（signature）、is_dangerous=false，但因可被辅助功能滥用，`malicious_signal=true`，不可因非 dangerous 而漏判）。

`custom_permissions` 数组每项对象：

| 子字段 | 类型 | 提取方法 | 默认空值 |
|---|---|---|---|
| `name` | string | 自定义权限名 | `""` |
| `protection_level` | string | 自定义权限保护级别 | `""` |

`uses_features` 数组每项对象：

| 子字段 | 类型 | 提取方法 | 默认空值 |
|---|---|---|---|
| `name` | string | feature 名（如 `android.hardware.telephony`） | `""` |
| `required` | boolean | 是否 required="true" | `false` |

### 3.4 `components`（对象）

> 对象默认空值示例：`{ "suspicious_activities":[], "suspicious_services":[], "suspicious_receivers":[], "suspicious_providers":[], "component_export_summary":{...} }`

**总判断思路**：先枚举 Manifest 中所有四大组件及其属性（exported、permission、intent-filter 等），再结合 jadx MCP 反编译出的源码判断各标志位，最后大模型筛选出"可疑"组件填入各 suspicious 数组。非可疑组件不列入。

#### 3.4.1 `suspicious_activities`（array）

数组每项对象字段：

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `class_name` | string | Activity 全类名（如 `com.example.MainActivity`） | Manifest + jadx MCP | `""` |
| `is_exported` | boolean | 是否 exported="true"（可被外部启动） | Manifest `android:exported`、无显式值结合 intent-filter 推断 | `false` |
| `is_main_entry` | boolean | 是否为启动入口（intent-filter 含 MAIN + LAUNCHER） | Manifest intent-filter / jadx MCP | `false` |
| `is_hidden` | boolean | 是否为隐藏 Activity（无 LAUNCHER 且通常不下发图标等） | 大模型基于 manifest/图标是否主入口判断 | `false` |
| `is_transparent` | boolean | 主题是否为透明（可用于悬浮窗钓鱼/伪装） | 检查该 activity 主题/res style | `false` |
| `hide_from_recent_tasks` | boolean | 是否从最近任务隐藏（`android:excludeFromRecents` 或 `FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS`） | Manifest + jadx MCP 反编译源码 | `false` |
| `suspicion_reason` | string | 为何判定为可疑的中文说明 | 大模型综合生成 | `""` |

**可疑 Activity 典型特征**（供大模型筛选）：透明主题 + 导出、隐藏图标、excludeFromRecents、加载远程/动态类、用于钓鱼覆盖层等。

#### 3.4.2 `suspicious_services`（array）

数组每项对象字段：

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `class_name` | string | Service 全类名 | Manifest + jadx MCP | `""` |
| `is_exported` | boolean | 是否导出 | Manifest | `false` |
| `is_foreground` | boolean | 是否前台服务（`startForeground` 调用） | jadx MCP 反编译获取可读源码后，在该源码上检索 `startForeground` 相关调用点，交由大模型结合上下文判定 | `false` |
| `has_keepalive_logic` | boolean | 是否有保活逻辑（如 START_STICKY、重启自身、双进程守护） | jadx MCP 反编译获取可读源码后，在该源码上检索 `START_STICKY`、双进程守护、重启自身等保活 API/逻辑，交由大模型结合上下文判定 | `false` |
| `is_accessibility_service` | boolean | 是否为无障碍服务（`BIND_ACCESSIBILITY_SERVICE` + accessibilityservice 配置） | Manifest + 资源配置 | `false` |
| `is_device_admin` | boolean | 是否为设备管理器（`BIND_DEVICE_ADMIN` + DeviceAdminReceiver） | Manifest | `false` |
| `has_dynamic_code_loading` | boolean | 是否动态加载代码（反射 `DexClassLoader`/`loadClass`） | jadx MCP 反编译获取可读源码后，在该源码上检索 `DexClassLoader`、`loadClass`、`defineClass` 等动态加载调用点，交由大模型结合上下文判定 | `false` |
| `has_jni_call` | boolean | 是否调用 so 原生库（`System.loadLibrary`/`native` 方法） | jadx MCP 反编译获取可读源码后，在该源码上检索 `System.loadLibrary`/`load`、`native` 方法声明等调用点，交由大模型结合上下文判定 | `false` |
| `suspicion_reason` | string | 可疑原因中文说明 | 大模型生成 | `""` |

#### 3.4.3 `suspicious_receivers`（array）

数组每项对象字段：

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `class_name` | string | Receiver 全类名 | Manifest + jadx MCP | `""` |
| `is_exported` | boolean | 是否导出 | Manifest | `false` |
| `listens_boot_completed` | boolean | 是否监听 `BOOT_COMPLETED` 广播（开机自启） | intent-filter + jadx MCP 反编译源码 | `false` |
| `listens_sms_received` | boolean | 是否监听 `SMS_RECEIVED` / `SMS_DELIVERED` 短信广播 | intent-filter + jadx MCP 反编译源码 | `false` |
| `listens_connectivity_change` | boolean | 是否监听网络变化广播 | intent-filter + jadx MCP 反编译源码 | `false` |
| `listens_package_added` | boolean | 是否监听 `PACKAGE_ADDED` 广播 | intent-filter + jadx MCP 反编译源码 | `false` |
| `aborts_broadcast` | boolean | 是否调用 `abortBroadcast()`（拦截短信常用） | jadx MCP 反编译 | `false` |
| `has_sms_intercept` | boolean | 是否具备短信拦截能力（监听短信 + abortBroadcast 任一信号） | 综合判断 | `false` |
| `is_dynamic_only` | boolean | 是否仅通过代码动态注册（Manifest 中无此 receiver） | Manifest 对比 jadx 反编译的动态注册代码（registerReceiver） | `false` |
| `intercept_mode` | string | 短信拦截模式（如 "abort_broadcast"/"content_observer"/"高优先级接收"），无则 `""` | jadx MCP 反编译 + 大模型判断 | `""` |
| `is_dynamic` | boolean | 是否动态注册（`registerReceiver`） | jadx MCP 反编译 | `false` |
| `suspicion_reason` | string | 可疑原因中文说明 | 大模型生成 | `""` |
| `risk_level` | string | 风险等级 CRITICAL/HIGH/MEDIUM/LOW | 大模型判断 | `""` |

#### 3.4.4 `suspicious_providers`（array）

数组每项对象字段：

| 子字段 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `class_name` | string | ContentProvider 全类名 | Manifest + jadx MCP | `""` |
| `is_exported` | boolean | 是否导出 | Manifest | `false` |
| `read_permission` | string | readPermission（可为空） | Manifest | `""` |
| `write_permission` | string | writePermission（可为空） | Manifest | `""` |
| `has_data_leak_risk` | boolean | 导出且无读写权限限制导致数据泄露风险 | 大模型判断 | `false` |
| `has_arbitrary_file_read` | boolean | 是否存在任意文件读取漏洞（如 `openFile` 无授权） | jadx MCP 反编译 + 大模型判断 | `false` |
| `has_rce_risk` | boolean | 是否存在远程代码执行风险（SQL 注入/反序列化等） | jadx MCP 反编译 + 大模型判断 | `false` |
| `is_sdk_provider` | boolean | 是否为第三方 SDK 提供的 provider | 包名对比常见 SDK | `false` |
| `suspicion_reason` | string | 可疑原因中文说明 | 大模型生成 | `""` |
| `risk_level` | string | 风险等级 | 大模型判断 | `""` |

#### 3.4.5 `component_export_summary`（对象）

> 提供各组件总量与导出数量的统计汇总。字段如下（均为 integer，默认空值 0）：

| 子字段 | 类型 | 默认空值 |
|---|---|---|
| `activity_total` | integer | `0` |
| `activity_exported` | integer | `0` |
| `service_total` | integer | `0` |
| `service_exported` | integer | `0` |
| `service_accessibility_count` | integer | `0` |
| `receiver_total` | integer | `0` |
| `receiver_exported` | integer | `0` |
| `provider_total` | integer | `0` |

> 提取方法：python 统计 Manifest 各组件的 total 与 exported 数量；`service_accessibility_count` 统计当前应用中无障碍服务数量。

---

## 四、全局约束（本子文件重申）

1. **无 `null`**：所有写出的字段值只能为规定类型及其默认空值，严禁写 `null`。
2. **工具次序**：jadx MCP 优先；androguard 作补充与失败替代。
3. **静态 vs 动态**：读取/解析/统计用 python 与 jadx 完成；主观综合（suspicion_reason、risk_level、malware_family、subject_anomaly、component 可疑筛选等）由大模型完成。
4. **输出完整性**：所有 array/object 必须按本表字段全部填充，即使某项无可疑也要写入默认空值对象/空数组。
5. 本子文件**只负责**上述 4 个顶级字段，其余字段由子02/03/04 负责，互不冲突，可并行执行。
6. **权限等级判定**：所有权限的 permissions_level / protection_level 一律以 `resource/permission_mapping.json` 为准（键=权限全名，值=级别字符串，可能含 `|` 分隔，如 `dangerous|appop`）。查询不到该权限名时其 permissions_level 记 `normal`；`is_dangerous` 统一用 `level.strip()` 含子串 `dangerous` 判定，查不到记 `false`。
