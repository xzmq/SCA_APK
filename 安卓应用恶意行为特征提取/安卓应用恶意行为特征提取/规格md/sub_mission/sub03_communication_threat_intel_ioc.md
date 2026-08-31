# 子03：通信与威胁情报 IOC 解析规格

> 本文档是「安卓应用恶意行为特征提取」规格主文件拆分出的**子文件**。本子文件由**子 agent** 负责执行，用于解析目标 APK 的**顶级字段 `c2_communication`** 与 **`iocs`** 两个字段。
>
> 本子文件面向**完全没有接触过安卓应用恶意行为解析的大模型**编写。你仅凭本文档，就应能完整、准确地提取并填充目标字段**所有**子字段，不得出现 `null` 值。

---

## 一、本子文件负责的顶级字段覆盖清单

| 顶级字段 | 含义 | 本文件负责的深度 |
| --- | --- | --- |
| `c2_communication` | 命令与控制（C2）通信相关分析结果 | 全量（含全部子字段、嵌套数组） |
| `iocs` | 威胁情报指标（IOC：URL / IP / 域名 / 解密结果 / 钱包地址） | 全量（含全部子字段、嵌套数组） |

> 其余顶级字段由其他子 agent 负责，本子文件**不**解析。当你在分析过程中发现的信息（如恶意行为、权限）同时服务于其他字段时，仅需把与本文件字段相关的内容填入本文件即可，不要越权填充其他字段。

---

## 二、解析所需文件

| 文件 / 数据源 | 用途 | 获取方式 |
| --- | --- | --- |
| `AndroidManifest.xml` | 判断是否允许明文流量（`cleartext_traffic_permitted`）、网络权限、自定义 `network_security_config` | jadx MCP / androguard 反编译 |
| DEX 字节码反编译源码 | 提取所有网络请求、加密、URL / IP / 域名字符串、命令字串、钱包地址 | jadx MCP 反编译、python 静态提取 |
| 反编译源码中的字符串常量表 | 提取 `http/https` URL、IP、域名，判断是否加密、请求方法、数据格式 | python 脚本扫描字符串 |
| 反编译源码中的加解密逻辑 | 解密 C2 密文样本，得到 `decrypted_result` | python 调用可用算法库或大模型辅助判断 |

> **工具优先级（强制）**：
> 1. **jadx MCP 是主要提取工具**，优先使用它反编译 APK、读取源码与字符串。
> 2. **androguard 仅用于补充**（如 `AndroidManifest.xml` 某些属性、权限、DEX 结构信息）以及**jadx MCP 提取失败时的替代选择**。
> 3. 所有**静态解析**（扫描字符串、正则匹配、去重、统计）一律使用 **python 脚本**实现；**代码/字节层反编译检索与调用点定位使用 jadx MCP 反编译**；所有需要**动态综合判断**（判断某域名是否可疑、某串是否为加密密文、整体是否为 C2）交由**大模型**完成。

---

## 三、字段级解析

下面按字段逐一展开。**凡标注「类型」为 对象/数组 的，其中的每一个子字段都要填写完整；凡标注「默认空值」的，是该字段在该特征不存在时填写的取值，绝不允许出现 `null`。**

### 3.1 `c2_communication`（命令与控制通信分析）

**解析目标**：判断该 APK 是否使用了命令与控制（C2）机制，并详细描述其服务器地址、加密方式、通信模式、命令集等。

#### 3.1.1 顶级布尔与基础信息

| 字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| `has_c2` | 布尔 | 该 APK 是否具备 C2 通信能力 / 采用 C2 架构 | 大模型综合判断。若代码中存在远端服务器地址 + 动态下发指令 / 心跳 / 接收命令执行等特征，判为 `true`；否则 `false` | `false` |
| `c2_servers` | 数组（每项为对象） | C2 服务器列表 | 见 3.1.2 | `[]` |
| `encrypted_c2_indicators` | 数组（每项为对象） | 加密的 C2 通信指示（密文样例、已解密结果等） | 见 3.1.3 | `[]` |
| `c2_communication_pattern` | 对象 | C2 通信模式（使用的协议/技术明细） | 见 3.1.4 | `{}` |
| `cleartext_traffic_permitted` | 布尔 | 是否允许明文 HTTP 流量 | 查看 `AndroidManifest.xml` 的 `usesCleartextTraffic` 属性，以及是否配置了 `network_security_config` 允许明文。为 `true` 表示允许明文传输 | `false` |
| `c2_command_categories` | 字符串数组 | C2 命令的分类集合 | 见 3.1.5 | `[]` |
| `c2_commands` | 数组（每项为对象） | C2 命令明细 | 见 3.1.6 | `[]` |

#### 3.1.2 `c2_servers`（C2 服务器列表，每项为对象）

> 数组内每一项是一个**域名分组的 C2 服务器记录**。同一域名的多个 URL 被合并为一条记录，通过 `paths` 数组列出各路径，`url_count` 记录合并的 URL 数量。没有则数组为空 `[]`。

**静态过滤规则（强制）**：`c2_servers` 必须经过纯静态过滤后填充，不得将所有从 DEX 字符串中提取的 URL 一律计入。下列 8 类 URL 必须排除：

1. **格式化模板 URL**：含 `%s` / `%d` / `%{name}` / `{0}` / `${name}` 等占位符（如 `http://%s:%d/%s`）；
2. **特殊保留 URL**：`about:blank` / `data:` / `javascript:` / `file://` / `mailto:` / `intent://` / `market://` / `content://` / `sms:` / `tel:` 等；
3. **XML 命名空间 / Schema URL**：`schemas.android.com` / `www.w3.org` / `ns.adobe.com` / `schemas.xmlsoap.org` / `schemas.microsoft.com` 等；
4. **良性 SDK URL**：广告 / 统计 / 推送 / 第三方登录 / 地图 / 崩溃上报类域名，采用精确后缀匹配，白名单见 `extract_c2_iocs.py` 中 `_BENIGN_SDK_DOMAINS`；
5. **私有 / 保留 IP**：`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`127.0.0.0/8`（loopback）、`169.254.0.0/16`（link-local）、`224.0.0.0/4`（multicast）、`240.0.0.0/4`（reserved）、`192.0.2.0/24`/`198.51.100.0/24`/`203.0.113.0/24`（TEST-NET）；
6. **疑似 OID 片段**：形如 `1.3.6.1` / `1.12.1.3` 等首段 0–5 且所有段 ≤ 100 的「IP」（多为 X.509/LDAP/SNMP OID）。
7. **不完整域名**：host 必须含至少 1 个点分隔 2 段（每段 ≥2 字符），不以点结尾，不含 `|` 等特殊字符（拒绝 `https://api.`、`http://hostname/?` 等代码模板片段）；
8. **代码模板占位符**：拒绝含 `hostname`、`state/path`、`your_`、`example`、`placeholder`、`domain.com`、`xxx`、`foo`、`bar` 等占位符的 URL。

**`is_suspicious_domain` 与 `domain_risk` 的静态判定**：统一使用 `_is_suspicious_domain()` 与 `_assess_domain_risk()` 基于上述白名单 + 可疑 TLD（`tk/ml/ga/cf/gq/top/xyz/club/icu`）+ 长随机子域名启发式（`^[a-z0-9]{10,}\.`）静态判定。

| 子字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| `url` | 字符串 | 该域名的代表 URL（合并组中的第一条） | 从反编译源码字符串常量、网络请求代码中提取完整 URL；必须通过 8 类静态过滤规则 | `""` |
| `domain` | 字符串 | 域名（或 IP） | 从 URL 提取域名，IP 类 URL 用 IP 作为分组键 | `""` |
| `paths` | 字符串数组 | 该域名下的 URL 路径列表（最多 10 条） | 从同域名的各 URL 提取 path 部分，去重 | `[]` |
| `url_count` | 整数 | 合并到本记录的 URL 数量 | python 统计同域名的 URL 数 | `0` |
| `ip` | 字符串 | 该服务器的 IP 地址 | 从 URL 提取硬编码 IP；若无 IP 则留空 | `""` |
| `protocol` | 字符串 | 通信协议（如 `http`、`https`、`TCP`、`UDP`、`ws` 等） | 从 URL scheme、Socket 使用方式判断 | `""` |
| `is_encrypted` | 布尔 | 与该服务器通信是否加密 | 依据是否使用 https、是否对上行/下行数据做加密处理判断 | `false` |
| `encryption_method` | 字符串 | 加密方法（如 `AES`、`RSA`、`DES`、`RC4` 等，若未加密则 `""`） | 从加解密代码使用的算法类、Key 处理逻辑判断 | `""` |
| `request_method` | 字符串 | HTTP 请求方法（`GET` / `POST` 等） | 从网络请求代码（如 `getInput`/`doOutput`、`setRequestMethod`）判断 | `""` |
| `data_format` | 字符串 | 传输数据格式（如 `json`、`xml`、`protobuf`、`raw`、`urlencoded` 等） | 从请求体构造代码、Content-Type、序列化方式判断 | `""` |
| `cleartext` | 布尔 | 该服务器通信是否使用明文（未加密） | 由 `is_encrypted` 反推；未加密则为 `true` | `false` |
| `is_suspicious_domain` | 布尔 | 该域名是否可疑 | **静态判定**：通过 `_is_suspicious_domain()` 基于良性 SDK 白名单做精确后缀匹配，命中则 `false`；否则 `true` | `false` |
| `domain_risk` | 字符串 | 域名风险程度（如 `low`、`medium`、`high`） | **静态判定**：通过 `_assess_domain_risk()` 评定——白名单 `low` / 可疑 TLD 或长随机子域名 `high` / 其余 `medium` | `""` |

#### 3.1.3 `encrypted_c2_indicators`（加密 C2 指示，每项为对象）

> 数组中每一项对应一段加密的 C2 通信指示。若没有加密 C2 指示则数组为空 `[]`。

**确定性源码搜索（强制）**：当 Phase 0.5 的 jadx CLI 反编译源码可用时，使用 `_find_encrypted_indicators_from_decompiled()` 确定性路径（替代非确定性 jadx MCP 搜索）。核心原则：

- **密文候选仅从 crypto 类上下文收集**：仅从含 `Cipher.getInstance` 或 `SecretKeySpec` 的 `.java` 源文件中提取 hex 字符串字面量作为密文候选，不再从全量 DEX 字符串中收集（消除哈希值、证书指纹、常量等假阳性）。
- **Fix A（算法-密文关联）**：每条 hex 字符串只与**同一 .java 文件**中检测到的算法配对尝试解密，不跨文件混合算法。
- **Fix B（密钥-密文区分）**：hex 字符串值若与同一文件中已提取的密钥值匹配（直接值、ASCII hex 编码、byte[] 值三种比对），则判定为密钥而非密文，跳过。同时过滤已知 hex 查找表（如 `0123456789ABCDEF`）。
- **RSA 跳过**：RSA 是非对称加密，无私钥无法暴力解密，自动跳过 RSA 算法的密文候选。

**解密尝试**：`_try_decrypt()` 支持 DES-ECB/CBC/CFB8、AES-ECB/CBC（含 NoPadding）、RC4；当对称解密全部失败时，`_try_xor_decrypt()` 使用跨文件密钥池做 XOR 兜底。解密结果通过 `_is_valid_decryption()` 严格验证（仅接受 URL/IP/路径模式）。

| 子字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| `encryption_algorithm` | 字符串 | 所用加密算法（如 `DES/ECB/PKCS5Padding`、`AES/CBC/NoPadding`、`XOR`） | 从 `Cipher.getInstance("...")` 字符串解析算法/模式/填充三段；XOR 兜底时填 `XOR` | `""` |
| `ciphertext_sample` | 字符串 | 加密后的密文样例（hex 表示，截断至 64 字符） | 从 crypto 类源文件中提取 hex 字符串字面量 | `""` |
| `decrypted_result` | 字符串 | 对密文解密后得到的结果 | Python 脚本调用对应解密算法还原；优先 byte[] 密钥，其次字符串密钥，最后 XOR 兜底；若所有尝试失败才留空 | `""` |
| `purpose` | 字符串 | 该加密指示的用途（如 `C2服务器地址`、`配置参数/路径片段`、`加密配置字符串`） | 依据解密结果内容判定：以 `http(s)://` 开头或含 IP → `C2服务器地址`；含 `/`/`?`/`=` → `配置参数/路径片段`；其余 → `加密配置字符串` | `""` |
| `key_or_pattern` | 字符串 | 用于解密的密钥或密钥规律模式 | 从源码中提取硬编码密钥字符串、`byte[]` 数组（标注「硬编码byte[]密钥」）或密钥推导逻辑；XOR 兜底时填「硬编码byte[]密钥」 | `""` |

#### 3.1.4 `c2_communication_pattern`（通信模式，对象）

> 本节 7 个布尔位 + 1 个字符串，逐项判断该 APK 使用了哪些通信方式。

| 子字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| `uses_http_cleartext` | 布尔 | 是否使用明文 HTTP 通信 | 检测代码中是否出现 `http://` 请求、非 https 的连接 | `false` |
| `uses_https` | 布尔 | 是否使用 HTTPS 通信 | 检测 `https://` 请求、TLS 相关代码 | `false` |
| `uses_socket_direct_connection` | 布尔 | 是否直接使用 Socket 连接 | 检测 `Socket`、`ServerSocket`、`DatagramSocket` 等类调用 | `false` |
| `uses_http_url_connection` | 布尔 | 是否使用 `HttpURLConnection` | 检测 `HttpURLConnection`、`URLConnection` 类 | `false` |
| `uses_dynmaic_url_resolution` | 布尔 | 是否使用动态 URL 解析（如 DGA、动态拼接域名） | **注意：这是模板原文的拼写（`dynmaic`），必须原样保留，不得修改为 `dynamic`。** 检测是否有运行时拼接 / 动态生成 URL 的逻辑 | `false` |
| `has_retry_mechanism` | 布尔 | 是否具备重试机制 | 检测循环重连、指数退避、失败后重试逻辑 | `false` |
| `data_exfiltration_format` | 字符串 | 数据外传格式（如 `json`、`xml`、`plain`） | 从外传数据构造代码判断；当 `malicious_behavior.data_exfiltration=true` 时此项必须有值 | `""` |

#### 3.1.5 `c2_command_categories`（命令分类集合，字符串数组）

**解析目标**：C2 下发的指令类别，如 `信息采集`、`文件上传`、`执行命令`、`截屏`、`录音`、`定位`、`自毁` 等。每取到一个类别，就往数组中增加一个字符串。

- **提取方法**：从反编译源码中查找指令分发 / 解析逻辑（如 `switch(command)`、`if (cmd.equals(...))`），枚举所有可能的命令分支，依据语义聚合成类别。若无法归类，则描述该命令时在 `c2_commands` 中填写。
- **默认空值**：`[]`（无命令分类时）。
- **注意**：若某 APK 的命令局限在某个明确集合内（如只有 `heartbeat`、`upload`、`download`），应把命令实际所在的类别逐个**明确列举**出来，而非写模糊的「各类命令」。

#### 3.1.6 `c2_commands`（C2 命令明细，每项为对象）

> 数组内每一项是一条具体的 C2 命令。

| 子字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| `command_id` | 字符串 | 命令的 ID / 标识符 | 从指令分发代码中提取命令字符串 / 编号 | `""` |
| `action` | 字符串 | 命令触发的动作（如 `上传文件`、`执行Shell`、`读取短信`） | 从命令处理逻辑判断 | `""` |
| `description` | 字符串 | 命令作用的文字说明 | 大模型结合代码行为撰写一句说明 | `""` |

---

### 3.2 `iocs`（威胁情报指标）

**解析目标**：汇总该 APK 关联的威胁情报指标，包括 C2 的 URL / IP / 域名、解密出来的 URL、加密货币钱包地址等。**本字段与 `c2_communication` 有强交叉引用关系，必须保持一致性（见 3.3）。**

#### 3.2.1 字符串数组类指标

| 字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| `c2_urls` | 字符串数组 | **解密结果中额外的** C2 URL（不在 `c2_servers[].url` 中的） | 从 `encrypted_c2_indicators[].decrypted_result` 提取 URL 形结果，排除已在 `c2_servers` 中的 | `[]` |
| `c2_ips` | 字符串数组 | C2 相关的 IP 列表 | 从 `c2_servers[].ip` 提取去重 | `[]` |

> **变更说明**：`iocs.c2_urls` 不再复制 `c2_servers[].url`（避免冗余）。`c2_servers[].url` 是 C2 服务器 URL 的权威来源；`iocs.c2_urls` 仅包含解密后发现的、不在 `c2_servers` 中的额外 URL。`suspicious_domains` 字段已删除（与 `suspicious_domains_detail` 100% 重复），域名详情统一由 `suspicious_domains_detail` 承载。`decrypted_urls` 字段已删除（与 `encrypted_c2_indicators[].decrypted_result` 100% 重复），解密结果统一由 `encrypted_c2_indicators` 承载。

#### 3.2.2 `crypto_wallet_addresses`（加密货币钱包地址，对象）

> 对象内含 4 个字符串数组，分别对应 4 种主流币种的钱包地址。该币种下没有检测到地址则对应数组为空 `[]`。

| 子字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| `BTC` | 字符串数组 | 比特币钱包地址列表 | 用正则匹配比特币地址格式（如 `1`/`3`/`bc1` 开头，长度与校验规则），扫描源码字符串 | `[]` |
| `ETH` | 字符串数组 | 以太坊钱包地址列表 | 用正则匹配 `0x` 开头的 40 位十六进制地址，扫描源码字符串 | `[]` |
| `XMR` | 字符串数组 | 门罗币钱包地址列表 | 用正则匹配门罗币地址格式，扫描源码字符串 | `[]` |
| `TRX` | 字符串数组 | 波场（Tron）钱包地址列表 | 用正则匹配 `T` 开头的 Base58 波场地址，扫描源码字符串 | `[]` |

> **提取说明**：使用 python 脚本对反编译源码做正则扫描，命中即为入列。该类地址通常与勒索、矿池收款等行为关联。

#### 3.2.4 `suspicious_domains_detail`（可疑域名详细列表，每项为对象）

> 数组内每一项对应一个可疑域名的详情。域名来源为 `c2_servers[].domain`（含 IP 作为域名回退）。本字段是域名信息的**唯一权威来源**（`suspicious_domains` 字符串数组已删除）。

| 子字段名 | 类型 | 解析目标 | 提取方法 | 默认空值 |
| --- | --- | --- | --- | --- |
| `domain` | 字符串 | 域名 | 从 `c2_servers[].domain` 提取，IP 视为域名回退 | `""` |
| `purpose` | 字符串 | 该域名用途（如 `c2_communication`） | python 静态判定（当前固定为 `c2_communication`） | `""` |
| `suspicious_level` | 字符串 | 可疑级别（`low`/`medium`/`high`） | python 静态判定：`_assess_domain_risk()` 基于良性域名白名单 + 可疑 TLD + 长随机子域名启发式 | `""` |

---

### 3.3 字段间交叉引用与一致性规则（强制）

> `iocs` 与 `c2_communication` 的分析结果必须互相印证，保证一致。请按下述规则核对，防止矛盾：

1. **`iocs.c2_urls` ⊆ (`encrypted_c2_indicators[].decrypted_result` URL 形) − (`c2_servers[].url`)**：`iocs.c2_urls` 仅包含解密结果中**不在** `c2_servers` 里的额外 URL，不应与 `c2_servers[].url` 重复。
2. **`iocs.c2_ips` == `c2_servers[].ip`（并集）**：`c2_servers` 里出现的 IP 都应在 `iocs.c2_ips` 中出现；反之亦然。
3. **`suspicious_domains_detail[].domain` 与 `c2_servers[].domain` 对应**：C2 服务器的域名应出现在 `suspicious_domains_detail` 中。
4. **`c2_command_categories` 若局限于某命令集，必须明确列举**：不能用一个笼统的类别掩盖真实命令范围。
5. **与 malicious_behavior.has_c2_communication 的交叉关系**：`has_c2_communication` 是布尔值（存在C2通信），`c2_servers` 是具体服务器列表。当 `has_c2_communication=true` 但 `c2_servers=[]` 时，说明存在网络通信但未找到硬编码URL，可能使用了动态域名解析，应在 `c2_communication_pattern.uses_dynmaic_url_resolution` 中进一步确认。

---

## 四、全局约束

1. **不允许出现 `null`**：所有字段一律填充默认空值——字符串 `""`、数字 `0`、布尔 `false`、数组 `[]`、对象 `{}`。
2. **工具优先级**：jadx MCP 为主，androguard 仅补充及 jadx MCP 失败时的替代。
3. **静态 vs 动态**：遍历/统计等**静态解析一律用 python 脚本**，**代码反编译检索与调用点定位使用 jadx MCP 反编译**；判断可疑性、综合拟写描述、决定是否为 C2 等**动态综合判断交给大模型**。
4. **保留模板拼写**：一切字段名严格照抄模板，绝不「纠正」可能的笔误（如 `uses_dynmaic_url_resolution` 中的 `dynmaic`）。
5. **并行执行**：本子文件与其他子文件（子01、子02、子04）所解析字段互不依赖，可与其他子 agent 并行分析。
6. **字段完整**：凡出现在本文件字段覆盖清单中的字段（含嵌套数组/对象的全部子字段），输出 JSON 中必须全部存在，不得缺失。
