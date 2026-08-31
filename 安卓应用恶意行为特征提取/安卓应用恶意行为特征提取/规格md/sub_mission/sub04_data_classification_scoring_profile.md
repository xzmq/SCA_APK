# 规格md_子04：数据分类评分与综合画像

## 零、子任务说明（给子 Agent）

本子任务由主 Agent 调度启动。你负责从解析结果中汇总并生成 **4 个顶级字段** 的内容：

- `data_classification`（数据分类）
- `risk_dimension_scores`（风险分维度评分）
- `advertisement_analysis`（广告分析）
- `attack_profile`（攻击画像）

除极少数由 Python 静态脚本直接算出的值（如 SDK 包名匹配、行为布尔位、维度打分）外，绝大多数字段属于 **大模型动态综合判断** 结果。

**双阶段执行架构**：

- **Phase A（Python 静态计算）**：由 `extract_risk_profile.py` 执行，计算确定性字段：
  - `advertisement_analysis`（SDK 包名匹配 + 行为布尔位）
  - `attack_profile.c2_flow.destinations_summary`（C2 域名统计 + 协议分布）
  - `risk_score_inputs`（汇总行为布尔位 + C2 数量 + 权限统计作为 LLM 评分输入）
- **Phase B（LLM 动态综合）**：由 `llm_synthesis.py` 调用 `opencode run --agent sub04_synthesis` 执行：
  - 构造上下文 bundle（全量 sub01-03 JSON + Phase A 骨架）
  - LLM 合成 `data_classification`、`risk_dimension_scores`、`attack_profile`（不含已由 Python 计算的 `destinations_summary`）
  - Python 解析 LLM 响应中的 JSON，合并 Phase A 骨架
- **Python 兜底**：当 LLM 失败（超时/解析错误）或 `SKIP_LLM_SYNTHESIS=1` 环境变量设置时，使用 Python 硬编码逻辑生成兜底结果。

你应当：

1. 依赖其他子 Agent 已提取的结构化中间结果（APK 元数据、Manifest 组件、代码恶意行为、通信与威胁情报 IOC 等）作为评分与画像的依据。
2. 对本子任务所需的 **基础数据**（例如 SDK 依赖列表、广告 SDK 包名、行为标志位）先用 Python 静态脚本从解析文件中提取或计算。
3. 对 **总结、判断、画像** 类内容（风险等级定性、行为标签、攻击链、最终结论等）由你作为大模型综合推理给出，不允许只靠脚本硬编码。
4. 把最终 4 个字段的结构化结果返回给主 Agent，由主 Agent 汇入最终特征 JSON。

**本子任务所有输出都不允许出现 `null`**，一律使用默认空值（字符串用 `""`、数字用 `0`、布尔用 `false`、数组用 `[]`、对象用 `{}`）。

---

## 一、字段覆盖清单

| 顶级字段 | 主要解析工具 | 解析文件 |
|---|---|---|
| `data_classification` | 大模型动态综合 + Python 补充 | APK 元数据、Manifest、代码反编译结果 |
| `risk_dimension_scores` | 大模型动态综合 + Python 计算 | 其他子 Agent 汇总的中间结果 |
| `advertisement_analysis` | Python 静态匹配为主 + 大模型判断 | DEX 代码、依赖列表、Manifest |
| `attack_profile` | 大模型动态综合为主 | 全部已提取结果 |

---

## 二、解析所需文件

| 文件 | 用途 |
|---|---|
| `AndroidManifest.xml` | 组件、权限、SDK 声明、应用入口 |
| DEX 反编译源码（jadx 输出） | SDK 使用、恶意行为、混淆方案、广告行为 |
| APK 元数据 / 证书信息 | 开发者信息、签名证书主体 |
| 其他子 Agent 的结构化中间结果 | 通信 URL/IOC、恶意行为清单、权限统计等 |

---

## 三、逐字段级解析（完整展开所有子字段）

### 3.1 `data_classification`（数据分类）— 数组

说明：对应用行为涉及的敏感数据 / 恶意行为逐个给出分类判断。数组每一项是一个对象，大模型综合其他子 Agent 结果逐条定性。

**行为类别扩展（与 malicious_behavior 对齐）**：除已有的短信窃取、设备信息采集、C2通信、加密混淆、持久化驻留、反检测对抗、钓鱼攻击外，当 `malicious_behavior` 中以下新字段为 `true` 时，必须额外生成对应的分类条目：

| malicious_behavior 字段 | data_classification.category | subcategory | risk_level |
| --- | --- | --- | --- |
| `data_exfiltration` | 数据外传 | 设备指纹+网络外传 | CRITICAL |
| `sms_delete_capability` | 短信删除 | ContentResolver.delete | HIGH |
| `call_forwarding` | 呼叫转移劫持 | setCallForward | HIGH |
| `has_c2_communication` | C2通信 | 硬编码URL+网络请求 | CRITICAL |
| `dynamic_code_loading` | 动态DEX加载隐藏载荷 | DexClassLoader | HIGH |
| `encryption_hardcoded_key` | 硬编码加密 | Cipher+硬编码密钥 | HIGH |

| 字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `data_classification` | array | 行为 / 敏感数据分类条目集合 | 大模型根据恶意行为、数据外传点、组件行为逐条归纳 | `[]` |
| └ `category` | string | 主分类（如：数据外传 / 隐私窃取 / 短信拦截 / 广告欺诈等） | 大模型从行为性质归纳 | `""` |
| └ `subcategory` | string | 子分类（进一步细分） | 大模型结合具体行为细分 | `""` |
| └ `is_confirmed` | boolean | 该分类是否被确凿证据确认 | 大模型根据证据强度判断 | `false` |
| └ `evidence` | string | 佐证该分类的证据描述（代码位置、行为等） | 引用反编译代码 / IO包 / 行为日志 | `""` |
| └ `risk_level` | string | 风险级别（如 RED / ORANGE / YELLOW / GREEN） | 大模型根据危害程度定性 | `""` |

### 3.2 `risk_dimension_scores`（风险分维度评分）— 对象

说明：按 6 个风险维度分别打分，并给出总分。各维度分数是 大模型 依据其他子 Agent 提取的证据综合评定，`score` 由大模型在 0–10 范围内给分，`evidence` 可引用具体证据。

| 字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `risk_dimension_scores` | object(6 维度 + total) | 各维度风险评分 | 大模型综合评定 | `{}` |
| └ `data_exfiltration` | object | **数据外传** 维度评分 | 依据对外发送数据的通信点、URL、上传行为、`mb.data_exfiltration` 布尔值打分 | `{}` |
| └ `data_exfiltration.score` | number | 分数（0–10） | 大模型按证据强度给分 | `0` |
| └ `data_exfiltration.out_of` | number | 满分（固定 10） | 恒为 `10` | `10` |
| └ `data_exfiltration.risk_level` | string | 风险级别（RED/ORANGE/YELLOW/GREEN） | 大模型按分数定性 | `""` |
| └ `data_exfiltration.evidence` | string/array | 证据（可字符串或数组） | 引用外传点与通信证据 | `""`（或 `[]`） |
| └ `c2_remote_control` | object | **C2 远控** 维度评分 | 依据 C2 地址、`mb.has_c2_communication`、远控指令、`mb.dynamic_code_loading` 打分 | `{}` |
| └ `c2_remote_control.score` | number | 分数（0–10） | 大模型按证据强度给分 | `0` |
| └ `c2_remote_control.out_of` | number | 满分（固定 10） | 恒为 `10` | `10` |
| └ `c2_remote_control.risk_level` | string | 风险级别 | 大模型按分数定性 | `""` |
| └ `c2_remote_control.evidence` | string/array | 证据 | 引用 C2 域名 / IP / 指令 | `""`（或 `[]`） |
| └ `data_steal` | object | **数据窃取** 维度评分 | 依据敏感隐私读取、`mb.sms_delete_capability`、`mb.call_forwarding`、`mb.data_exfiltration` 打分 | `{}` |
| └ `data_steal.score` | number | 分数（0–10） | 大模型按证据强度给分 | `0` |
| └ `data_steal.out_of` | number | 满分（固定 10） | 恒为 `10` | `10` |
| └ `data_steal.risk_level` | string | 风险级别 | 大模型按分数定性 | `""` |
| └ `data_steal.evidence` | string/array | 证据 | 引用隐私读取与数据窃取代码 | `""`（或 `[]`） |
| └ `encryption_obfuscation` | object | **加密混淆** 维度评分 | 依据加解密、伪装、混淆方案、`mb.encryption_hardcoded_key` 打分 | `{}` |
| └ `encryption_obfuscation.score` | number | 分数（0–10） | 大模型按证据强度给分 | `0` |
| └ `encryption_obfuscation.out_of` | number | 满分（固定 10） | 恒为 `10` | `10` |
| └ `encryption_obfuscation.risk_level` | string | 风险级别 | 大模型按分数定性 | `""` |
| └ `encryption_obfuscation.evidence` | string/array | 证据 | 引用加密库、混淆特征、壳方案 | `""`（或 `[]`） |
| └ `persistence` | object | **持久化** 维度评分 | 依据开机自启、服务自启、保活等行为打分 | `{}` |
| └ `persistence.score` | number | 分数（0–10） | 大模型按证据强度给分 | `0` |
| └ `persistence.out_of` | number | 满分（固定 10） | 恒为 `10` | `10` |
| └ `persistence.risk_level` | string | 风险级别 | 大模型按分数定性 | `""` |
| └ `persistence.evidence` | string/array | 证据 | 引用自启组件、服务、Receiver | `""`（或 `[]`） |
| └ `anti_detection` | object | **反检测** 维度评分 | 依据防杀、检测规避、壳、Root 隐藏、`mb.dynamic_code_loading` 等打分 | `{}` |
| └ `anti_detection.score` | number | 分数（0–10） | 大模型按证据强度给分 | `0` |
| └ `anti_detection.out_of` | number | 满分（固定 10） | 恒为 `10` | `10` |
| └ `anti_detection.risk_level` | string | 风险级别 | 大模型按分数定性 | `""` |
| └ `anti_detection.evidence` | string/array | 证据 | 引用反检测代码与混淆特征 | `""`（或 `[]`） |
| └ `total` | object | 总分汇总 | 综合 6 维度得分 | `{}` |
| └ `total.score` | number | 总分（0–10 区间，6 维度平均） | 大模型综合 6 维度加权或求和 | `0` |
| └ `total.risk_level` | string | 整体风险级别（RED/ORANGE/YELLOW/GREEN） | 大模型按总分定性 | `""` |

> **变更说明**：`total.description` 字段已删除（与 `attack_profile.overall_judgment.summary` 语义重复）。整体风险描述统一由 `attack_profile.overall_judgment.summary` 承载。

### 3.3 `advertisement_analysis`（广告分析）— 对象

说明：识别应用集成的广告 SDK 与广告相关行为。`ad_sdk_list` 由 Python 静态脚本匹配 SDK 包名生成，`ad_behaviors` 由 Python 静态脚本识别代码中的行为标志位生成，大模型可对结果进行补充说明。

| 字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `advertisement_analysis` | object(SDK 列表 + 行为位) | 广告 SDK 与行为分析 | Python 匹配 + 大模型补充 | `{}` |
| └ `ad_sdk_list` | array | 检测到的广告 SDK 集合 | python 读取 resource/constant.py 的 `ALL_PACKAGE_SDK`/`ALL_PACKAGE_TYPE` 建立 `{包名前缀:(SDK名,[风险标签])}` 列表；双重扫描：(a) 用 **jadx MCP 反编译**代码中的 import/类名/字符串前缀匹配常量包名；(b) 扫描 Manifest 的 application 下 `<meta-data>` 的 `android:name` 值匹配常量键（如 `com.google.android.gms.ads.APPLICATION_ID`、`applovin.sdk.key`） | `[]` |
| └ `ad_sdk_list.sdk_name` | string | SDK 名称 | 取自 constant.py 的 \`ALL_PACKAGE_SDK\` 中匹配到的 SDK 名 | `""` |
| └ `ad_sdk_list.package_prefix` | string | SDK 包名前缀 | 双重扫描命中的常量包名键（\`ALL_PACKAGE_SDK\` 的键） | `""` |
| └ `ad_sdk_list.risk_level` | string | SDK 风险级别 | 取自 constant.py 的 `ALL_PACKAGE_TYPE` 对应风险标签（如 `HIGH_RISK_SKD`；多等级逗号分隔） | `""` |
| └ `ad_sdk_list.note` | string | 备注 | 大模型补充说明 | `""` |
| └ `ad_behaviors` | object(7 个布尔位) | 广告相关行为是否检出 | Python 静态识别代码 / Manifest 中的行为标志 | `{}` |
| └ `ad_behaviors.fullscreen_ad_detected` | boolean | 全屏广告 | Python 匹配全屏广告调用 | `false` |
| └ `ad_behaviors.notification_ad_detected` | boolean | 通知栏广告 | Python 匹配通知广告调用 | `false` |
| └ `ad_behaviors.lockscreen_ad_detected` | boolean | 锁屏广告 | Python 匹配锁屏广告调用 | `false` |
| └ `ad_behaviors.popup_ad_detected` | boolean | 弹窗广告 | Python 匹配弹窗广告调用 | `false` |
| └ `ad_behaviors.click_fraud_detected` | boolean | 点击欺诈（刷量） | Python 匹配模拟点击 / 刷量逻辑 | `false` |
| └ `ad_behaviors.overlay_ad_detected` | boolean | 悬浮 / 叠加层广告 | Python 匹配 overlay 窗口广告调用 | `false` |
| └ `ad_behaviors.silent_download_promotion` | boolean | 静默下载 / 推广安装 | Python 匹配静默下载 / 推广安装逻辑 | `false` |

### 3.4 `attack_profile`（攻击画像）— 对象

说明：对应用整体攻击画像进行综合刻画，绝大多数子字段由 **大模型动态综合** 输出，引用其他子 Agent 的结果。

| 字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
|---|---|---|---|---|
| `attack_profile` | object(13 子字段) | 完整攻击画像 | 大模型综合全部解析结果 | `{}` |
| └ `developer_subject` | string | 开发者 / 签名证书主体 | 大模型从证书 / 元数据综合（引用于子01） | `""` |
| └ `app_function_summary` | string | 应用功能总结 | 大模型从组件 / 代码功能总结 | `""` |
| └ `distribution_form` | string | 分发途径 / 形态 | 大模型从打包特征 / 分发渠道判断 | `""` |
| └ `core_framework` | string | 核心框架（如 Android SDK / 插件化框架 / React Native 等） | 大模型从代码结构判断 | `""` |
| └ `development_language` | string | 开发语言 | 大模型从代码 / 库识别（Java/Kotlin/原生等） | `""` |
| └ `obfuscation_solution` | string | 混淆 / 加固方案 | 大模型从混淆特征、加固壳识别 | `""` |
| └ `network_stack` | string | 网络协议栈（如 OkHttp / HttpURLConnection / Socket 等） | 大模型从网络库识别 | `""` |
| └ `encryption_library` | string | 加密库（如 AES / RSA / 自研加密） | 大模型从加密调用识别 | `""` |
| └ `c2_flow` | object | C2 通信流程 | 大模型依据通信与 IOC 结果还原 | `{}` |
| └ `c2_flow.decryption_step` | string | C2 流量解密步骤描述 | 大模型根据加密解密流程描述 | `""` |
| └ `c2_flow.destinations_summary` | object | C2 目标地址摘要（避免与 `c2_servers` 重复展开全部 URL） | 脚本汇总 C2 URL（来自子03 `c2_servers`） | `{"total_count":0,"unique_domain_count":0,"top_5":[],"protocol_distribution":{}}` |
| └ `c2_flow.destinations_summary.total_count` | integer | C2 目标地址总数 | 脚本统计 `c2_servers` 中 URL 数量 | `0` |
| └ `c2_flow.destinations_summary.unique_domain_count` | integer | 唯一域名数 | 脚本统计 `c2_servers[].domain` 去重数量 | `0` |
| └ `c2_flow.destinations_summary.top_5` | array | 前 5 条 C2 地址缩写 | 脚本取 `c2_servers[].domain` + URL 首 path 段拼接，截断至 50 字符 | `[]` |
| └ `c2_flow.destinations_summary.top_5.*` | string | 域名+路径缩写（≤50 字符） | 脚本从 `c2_servers[].domain` + path 拼接截断 | `""` |
| └ `c2_flow.destinations_summary.protocol_distribution` | object | 协议分布（键为协议名，值为计数） | 脚本按 `c2_servers[].protocol` 统计 | `{}` |
| └ `overall_judgment` | object | 总体判断 | 大模型综合判定 | `{}` |
| └ `overall_judgment.risk_label` | string | 风险标签（如 恶意 / 风险 / 正常） | 大模型定性 | `""` |
| └ `overall_judgment.risk_score` | number | 综合风险分数 | 大模型综合评分 | `0` |
| └ `overall_judgment.summary` | string | 总体结论描述 | 大模型总结全文 | `""` |
| └ `malware_family_indicators` | array | 恶意家族特征指标 | 大模型结合家族特征比对 | `[]` |
| └ `malware_family_indicators.indicator` | string | 指标名称（如家族签名 / 特殊字符串） | 大模型提取 | `""` |
| └ `malware_family_indicators.detail` | string | 指标详情 | 大模型说明 | `""` |
| └ `attack_chains` | array | 攻击链 | 大模型还原多阶段攻击过程 | `[]` |
| └ `attack_chains.chain_id` | string | 攻击链编号 | 大模型编号 | `""` |
| └ `attack_chains.name` | string | 攻击链名称 | 大模型命名 | `""` |
| └ `attack_chains.steps` | array | 攻击步骤集合 | 大模型分步还原 | `[]` |
| └ `attack_chains.steps.step_order` | number | 步骤序号 | 大模型编号（1 起） | `0` |
| └ `attack_chains.steps.behavior` | string | 该步骤行为 | 大模型描述 | `""` |
| └ `attack_chains.steps.target` | string | 该步骤目标 / 作用对象 | 大模型描述 | `""` |
| └ `attack_chains.description` | string | 攻击链整体描述 | 大模型总结 | `""` |
| └ `behavior_tags` | array | 行为标签 | 大模型归纳行为特征 | `[]` |
| └ `behavior_tags.tag` | string | 标签名（如 网络行为 / 隐私读取 / 持久化等） | 大模型归纳 | `""` |
| └ `behavior_tags.category` | string | 标签类别（如 网络行为 / 文件行为 / 隐私行为 / 进程行为等） | 大模型分类 | `""` |
| └ `behavior_tags.confidence` | integer | 置信度（0–100整数） | 大模型按证据强度给分（0-100的整数，非浮点数） | `0` |
| └ `behavior_tags.evidence` | string | 佐证证据 | 引用代码 / 行为证据 | `""` |

---

## 四、全局约束

1. **无 `null` 值**：任何字段都不允许为 `null`，一律使用默认空值（字符串 `""`、数字 `0`、布尔 `false`、数组 `[]`、对象 `{}`）。
2. **工具分工**：静态解析以 **jadx MCP** 为主，**androguard** 仅用于补充和 jadx MCP 提取失败后的替代方案。
3. **解析 / 计算与判断分工**：所有涉及静态解析、字段提取、数值计算（如 SDK 包名匹配、行为布尔位、分数初算）的环节使用 **Python 静态脚本** 实现；所有涉及 **动态综合、总结、定性判断、画像刻画** 的环节交给 **大模型**。
4. **并行执行**：本子 Agent 的任务可与其他子 Agent 并行启动，仅在需要引用其他子结果时等待其完成。
5. **返回主 Agent**：本子任务完成后，把 4 个顶级字段的结构化中间结果交回主 Agent 汇入最终 JSON。
