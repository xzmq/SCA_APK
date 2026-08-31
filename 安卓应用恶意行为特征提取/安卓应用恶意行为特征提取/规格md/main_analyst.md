# 安卓应用恶意行为特征提取规格（主文档 - 拆分版）

> 本文件为「安卓应用恶意行为特征提取规格」的拆分版**主文件**，对应**主 agent**。
> 主文件只包含总体信息与调度规则；各字段的具体解析目标、方法与流程，由**子 md 文件**分别定义，由**子 agent** 并行执行。
>
> 本文件为最高优先级规格文档，覆盖其下所有子文档中与本文件相冲突的内容。

---

## 一、输出目标

最终输出一个**安卓应用恶意行为特征 JSON**，其顶层字段结构定义与各字段含义，均以
`/Users/yqh/knowledge_graph/安卓应用恶意行为特征提取/终极_安卓应用恶意行为特征JSON模板.json` 为**唯一输出示例**。

输出 JSON 必须包含如下 **13 个顶级字段**（每个顶级字段的完整子字段要求见对应子 md）：

| 序号 | 顶级字段 | 对应子文档 |
| --- | --- | --- |
| 1 | `file_basic` | 子01 |
| 2 | `certificate_analysis` | 子01 |
| 3 | `permissions` | 子01 |
| 4 | `components` | 子01 |
| 5 | `code_analysis` | 子02 |
| 6 | `malicious_behavior` | 子02 |
| 7 | `native_analysis` | 子02 |
| 8 | `c2_communication` | 子03 |
| 9 | `iocs` | 子03 |
| 10 | `data_classification` | 子04 |
| 11 | `risk_dimension_scores` | 子04 |
| 12 | `advertisement_analysis` | 子04 |
| 13 | `attack_profile` | 子04 |

---

## 二、输入

- **单APK输入**：待分析的目标 APK 文件路径（`*.apk`）。
- **批量目录输入**：包含一个或多个 APK 文件的目录路径，脚本递归遍历查找所有 `.apk`。
- **输入示例（字段定义）**：`/Users/yqh/knowledge_graph/安卓应用恶意行为特征提取/终极_安卓应用恶意行为特征JSON模板.json`。

### CLI用法

- 单APK模式：`python run_pipeline.py <apk_path> <output_dir>` → 输出 `<output_dir>/<apk_name>.json`
- 批量目录模式：`python run_pipeline.py <input_dir> <output_dir>` → 输出 `<output_dir>/<relative_path>/<apk_name>.json`
  - APK 相对于 `<input_dir>` 的目录结构会被保留到输出目录中
  - 例如 `input_dir/sub/foo.apk` → `output_dir/sub/foo.json`

## 三、输出路径规则

- **单APK**：`<output_dir>/<apk_name_without_ext>.json`
- **批量目录**：`<output_dir>/<relative_path>/<apk_name_without_ext>.json`
  - `relative_path` 为 APK 所在目录相对于输入目录的相对路径
  - 与输入目录目录结构一致，便于追踪

## 四、jadx生命周期管理（批量模式强制）

每个 APK 的处理遵循以下生命周期：

0. **Phase 0：预处理**：计算 SHA256/MD5/SHA1，查询 `report_apk_mappings_new.xlsx` 匹配安全报告，解析 `known_behaviors`
0.5. **Phase 0.5：jadx CLI 全量反编译（确定性源码）**：使用 jadx CLI（`jadx` 二进制，非 jadx-gui）以 `--no-res -q --show-bad-code` 参数全量反编译 APK 到临时目录。产物供 sub03 确定性 crypto 分析（替代非确定性 jadx MCP 搜索）。300s 超时则降级继续。
1. **Phase 1：启动 jadx-gui**：加载目标 APK，等待 MCP HTTP 端口就绪
2. **Phase 2：执行 sub01/sub02/sub03**（并行）：sub03 接收 Phase 0.5 的反编译目录路径作为第三参数
2.5. **Phase 2.5：加壳检测与脱壳（条件触发）**：当 sub02 的 `_packing_assessment.confidence >= 60` 时触发：
   - **F-E-lite（静态脱壳）**：`unpacker.py` 定位加密 DEX → 提取 stub 密钥 → DES/AES/RC4/XOR 解密 → DEX magic 验证
   - **F-E-full（动态脱壳）**：`dynamic_unpacker.py` Frida 内存 DEX dump（需 Android 模拟器 + Frida 环境）
   - 成功后：`repacker.py` 重打包 APK → jadx CLI 重新反编译 → 重载 jadx-gui → 重跑 sub01/02/03
   - 失败时：F-D 降级策略（上调 risk_score + validation warning）
3. **Phase 3：执行 sub04**（串行）：Phase A（Python 静态计算）+ Phase B（LLM 合成 / Python 兜底）
4. **Phase 4：合并输出 + 跨字段校验**：聚合所有中间 JSON + `_cross_validate()` 7 条规则 → `validation_report`
5. **关闭 jadx-gui**：terminate 进程并等待退出
6. **清理 jadx cache**：调用 `clear_cache` 释放端口与缓存
7. **清理临时目录**：删除中间工作目录

**重要**：批量模式下，必须在上一个 APK 处理完毕后完整执行步骤 5-7，再加载下一个 APK，防止上下文污染。

---

## 五、使用工具

1. **jadx MCP（主要提取工具）**
   - 功能：反编译 APK（DEX → smali / Java 源码）、解析 AndroidManifest.xml、资源、证书、DEX 列表等。
   - 所有对 APK 的**静态解析**，优先使用 jadx MCP 完成。

2. **jadx CLI（确定性全量反编译）**
   - Phase 0.5 使用 jadx CLI 全量反编译 APK，产物供 sub03 确定性 crypto 类搜索与密钥提取。
   - 加壳 APK 脱壳后，对重打包 APK 再次执行 jadx CLI 反编译，确保 sub03 搜索解壳后的真实代码。

3. **androguard（补充 / 替代工具）**
   - 用途一：对 jadx MCP 提取**失败或缺失**的字段做**补充**；
   - 用途二：jadx MCP 无法完成时，作为**替代选择**。
   - 辅助处理：证书指纹、APK 熵值、DEX 数量、Manifest 补充解析等。

4. **Python 脚本（静态解析实现）**
   - 所有**静态计算**环节（熵值、哈希、dex 计数、弱算法识别、字符串/URL/IP 抽取等）必须用 Python 脚本实现。

5. **加壳检测与脱壳工具链**
   - `packer_signatures.py`：15+ 主流加固方案特征库（360/Bangcle/Ijiami/Tencent Legu/Alibaba 等）
   - `unpacker.py`：静态 DEX 重构（F-E-lite）——密钥提取 + DES/AES/RC4/XOR 解密 + DEX magic 验证
   - `dynamic_unpacker.py`：动态 Frida DEX dump（F-E-full）——需 Android 模拟器 + Frida server
   - `repacker.py`：DEX 合并重打包——替换加密 DEX + 删除壳文件 + 重新签名（原始 APK 不修改）

4. **大模型（动态解析 / 总结判断）**
   - 所有**语义判断、总结归纳、风险等级评定**环节交给大模型判断。

---

## 六、全局规则（所有子文档必须遵守）

1. **不允许出现 `null` 值**
   - 输出 JSON 中任何字段值都**不允许为 `null`**。
   - 无法确定 / 无数据的字段，必须使用该字段的**默认空值**：
     - 数组 → `[]`
     - 对象 → `{}`
     - 字符串 → `""`
     - 数字 → `0`
     - 布尔 → `false`
2. **静态 / 动态分工**
   - 所有涉及**静态解析**的环节使用 Python 脚本实现；
   - 所有涉及**动态解析 / 总结**的环节交给大模型判断。
3. **提取顺序**：jadx MCP 优先，androguard 补充 / 替代。
4. **可复现性**：提取脚本与结论应可重复执行，并记录所针对的 APK 哈希。
5. **一致性**：任何字段的取值类型、命名、嵌套结构必须与模板 JSON 完全一致。

---

## 七、子 agent 并行调度

主 agent 根据需求启动子 agent，执行各子 md 文件要求的任务。4 个子文档相互独立，**尽可能并行**执行：

- **sub_mission/sub01_static_metadata_manifest_cert_permissions.md** → 提取字段：`file_basic`、`certificate_analysis`、`permissions`、`components`
- **sub_mission/sub02_code_analysis_malicious_behavior.md** → 提取字段：`code_analysis`、`malicious_behavior`、`native_analysis`
- **sub_mission/sub03_communication_threat_intel_ioc.md** → 提取字段：`c2_communication`、`iocs`
- **sub_mission/sub04_data_classification_scoring_profile.md** → 提取字段：`data_classification`、`risk_dimension_scores`、`advertisement_analysis`、`attack_profile`

调度要求：

1. 每个子 agent 严格按对应子 md 中的字段定义与流程执行，输出该组字段的 JSON。
2. 各子 agent 尽量并行，互不依赖。
3. 子 agent 输出必须遵守「全局规则」（无 null、静态 python / 动态大模型、jadx MCP 优先）。

---

## 八、总结与复核（主 agent 负责）

1. 收集 4 个子 agent 的输出 JSON。
2. 合并为完整的顶级字段 JSON。
3. **F-B：填充 `file_basic.is_packed`**：从 `code_analysis._packing_assessment` 读取 `is_packed` + `confidence`，设置 `file_basic.is_packed`（修复死字段）。
4. **F-D：加壳降级策略**：当 `_packing_assessment.confidence >= 60` 时，上调 `attack_profile.overall_judgment.risk_score`（+2，cap 10），并在 `validation_report.warnings` 中添加加固警告。
5. **跨字段校验（`_cross_validate()`，7 条规则，非阻断）**：
   - Rule 1：全字段 null 扫描 → `null` 值替换为默认空值
   - Rule 2：`iocs.c2_urls` 不应与 `c2_servers[].url` 重复（新语义：c2_urls 仅含解密额外 URL）
   - Rule 3：`iocs.c2_ips` ⊇ `c2_servers[].ip`
   - Rule 4：`malicious_behavior.has_c2_communication` 与 `c2_communication.has_c2` 一致性
   - Rule 5：`components.suspicious_receivers[].has_sms_intercept` 与 `malicious_behavior.sms_intercept_*` 一致性
   - Rule 6：`risk_dimension_scores.total.risk_level` 与 `attack_profile.overall_judgment.risk_label` 量级一致（差异 ≥2 级告警）
   - Rule 7：`data_classification` 条目数与 `malicious_behavior=true` 行为数大致对应
6. 输出 `validation_report`（`{total_warnings, warnings[]}`）作为顶级字段。
7. 如有解壳信息，输出 `unpacking_info` 顶级字段（`was_packed`、`packer_name`、`confidence`、`unpacking_method`、`unpacked_dex_count` 等）。
8. 生成最终特征 JSON 与分析结论。

---

## 九、子文档清单

| 文件 | 覆盖顶级字段 |
| --- | --- |
| `sub_mission/sub01_static_metadata_manifest_cert_permissions.md` | `file_basic`、`certificate_analysis`、`permissions`、`components` |
| `sub_mission/sub02_code_analysis_malicious_behavior.md` | `code_analysis`、`malicious_behavior`、`native_analysis` |
| `sub_mission/sub03_communication_threat_intel_ioc.md` | `c2_communication`、`iocs` |
| `sub_mission/sub04_data_classification_scoring_profile.md` | `data_classification`、`risk_dimension_scores`、`advertisement_analysis`、`attack_profile` |
