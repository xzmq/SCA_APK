# 验证方案：恶意代码与恶意行为匹配性校验

## 目标

对批量分析产出的 3,476 个 `_vul_code.json` 结果文件，验证每个 `恶意代码` 片段是否真正对应其标注的 `恶意行为`。采用**两阶段架构**：规则匹配（快速过滤）+ LLM 语义复核（精准判断）。

## 输入

- 结果文件目录：`D:\SCA_APK\vul_code_result\malradar-{1,2,3}\*_vul_code.json`
- 共 3,476 个 JSON 文件，每个包含 0~N 个行为，每个行为下 0~N 个恶意代码片段

## 输出

- 验证不通过的结果：`D:\SCA_APK\verify\output\` 下，一个 APK 对应一个 JSON 文件
- 文件名：`<sha256>_verify_fail.json`
- 内容：验证不通过的行为、代码片段、失败原因

## 阶段一：规则匹配（0 token）

### 原理

对每种行为定义"期望关键词集合"，检查 `malicious_code_snippet` 是否至少命中一个关键词。未命中则标记为"可疑"，进入阶段二。

### 关键词规则

从 `behavior_rules.py` 的 `method_refs` 和 `strings` 字段提取，补充常见 API 名和关键词：

| 行为 | 期望关键词（snippet 中至少命中 1 个） |
|------|--------------------------------------|
| c2_communication | Socket, URLConnection, HttpURLConnection, OkHttpClient, newCall, Retrofit, connect, getResponseCode |
| sms_fraud | sendTextMessage, sendDataMessage, SmsManager, SMS_RECEIVED, SMS_DELIVER, abortBroadcast, sendMultipartTextMessage, 1066, 1069, smspay, wap, billing, subscribe |
| device_fingerprinting | getDeviceId, getImei, getSubscriberId, getLine1Number, getConfiguredNetworks, ANDROID_ID, Build.SERIAL, getMacAddress, TelephonyManager, getMeid, getSerial, Settings.Secure |
| location_tracking | getLastKnownLocation, requestLocationUpdates, LocationManager, FusedLocationProviderClient, getLastLocation, getAllProviders |
| keylogging | onAccessibilityEvent, getPrimaryClip, addPrimaryClipChangedListener, TYPE_VIEW_TEXT_CHANGED, TYPE_VIEW_FOCUSED, dispatchKeyEvent, ClipboardManager |
| ransomware | Cipher, doFinal, lockNow, resetPassword, DevicePolicyManager, encrypt, decrypt, listFiles, ransom, bitcoin, BTC, 赎金, 解锁 |
| banking_trojan | addView, WindowManager, TYPE_APPLICATION_OVERLAY, TYPE_SYSTEM_ALERT, password, passwd, login, signin, cvv, 银行卡, 密码, 账号, 验证码, LayoutParams |
| ad_fraud | InterstitialAd, loadAd, showAd, adView, Banner, ad_click, autoClick, clickAd, simulateClick, AdView, MobileAds |
| persistence | startService, startForegroundService, startForeground, BOOT_COMPLETED, WakeLock, FOREGROUND_SERVICE |
| root_exploitation | Runtime, exec, /system/bin/su, /system/xbin/su, Superuser, Magisk, busybox, superuser |
| dynamic_code_loading | DexClassLoader, PathClassLoader, loadClass, loadDex, ClassLoader |
| code_execution | Runtime, exec, ProcessBuilder, start, /system/bin/sh, chmod, busybox |
| anti_detection | isDebuggerConnected, ptrace, TracerPid, /proc/self/status, qemu, goldfish, ranchu, ro.kernel.qemu, DexProtector, bangcle, jiagu, tencentprotect, 360jiagu |
| social_spread | setAction, setPackage, android.intent.action.SEND, com.tencent.mm, com.tencent.mobileqq, com.whatsapp, ContactsContract |
| silent_install_uninstall | createSession, PackageInstaller, INSTALL_PACKAGES, application/vnd.android.package-archive, uninstall, DELETE, UNINSTALL_PACKAGE |
| screen_capture | MediaProjection, createScreenCaptureIntent, createVirtualDisplay, takeScreenshot, SurfaceControl, VirtualDisplay |
| camera_capture | Camera, openCamera, takePicture, IMAGE_CAPTURE, Camera.Parameters, CameraManager |
| mic_recording | AudioRecord, startRecording, MediaRecorder, setAudioSource, AudioSource.MIC, prepare, VOICE_CALL |
| call_operations | ACTION_CALL, ACTION_DIAL, CALL_PHONE, killBackgroundProcesses, forceStopPackage, killProcess, CallLog, call_log, VOICE_CALL, VOICE_UPLINK, VOICE_DOWNLINK, callRecord |
| browser_data_theft | browser/bookmarks, browser/history, BrowserContract, browser.bookmarks |
| calendar_theft | com.android.calendar, CalendarContract, CalendarContract.Events |
| wifi_password_theft | preSharedKey, WifiConfiguration, allowedKeyManagement, getConfiguredNetworks, WifiManager |
| file_access | listFiles, FileInputStream, FileOutputStream, getExternalStorageDirectory, File |
| overlay_attack | addView, WindowManager, TYPE_APPLICATION_OVERLAY, TYPE_SYSTEM_ALERT, TYPE_PHONE, LayoutParams |
| icon_hiding | setComponentEnabledSetting, hideIcon, DONT_HIDE_APP_ICON, COMPONENT_ENABLED_STATE_DISABLED, PackageManager |
| process_kill | killBackgroundProcesses, forceStopPackage, killProcess, ActivityManager |
| device_reboot | reboot, REBOOT, /system/bin/reboot, PowerManager |
| settings_modify | putString, Settings.System, Settings.Secure, Settings.Global, WRITE_SETTINGS |
| crypto_wallet_detection | BTC, bc1, 0x, ETH, XMR, TRX |

### 规则匹配流程

1. 遍历每个 `_vul_code.json` 文件
2. 提取 `行为列表` → 每个行为的 `恶意代码` 数组
3. 对每个代码片段，取 `malicious_code_snippet` 字段
4. 在 snippet 中搜索对应行为的"期望关键词"（不区分大小写）
5. 如果 snippet 中一个关键词都没命中 → 标记为"规则未通过"
6. 同时检查：
   - `class_path` 是否为空或格式异常（如不含 `L` 前缀或 `;` 后缀）
   - `malicious_code_snippet` 是否过短（< 20 字符）
   - `behavior_description` 是否为空或仅含模板文字（如"GLM 分析失败"）

### 阶段一输出

- 通过：snippet 中至少命中 1 个期望关键词
- 可疑：未命中任何关键词，或存在格式异常 → 进入阶段二

### 预估

- 3,476 文件 × 平均 5 对/文件 = ~17,000 对
- 规则未通过预计 5-10%：~850-1,700 对
- 耗时：2-5 分钟（纯 Python，无 LLM）
- Token：0

## 阶段二：LLM 语义复核（qwen3.7-plus）

### 原理

对阶段一标记为"可疑"的 behavior-code pair，调用 qwen3.7-plus 做语义判断：这段代码是否真的实现了该恶意行为？

### LLM Prompt 模板

```
你是 Android 安全审计专家。请判断以下代码片段是否真正实现了标注的恶意行为。

恶意行为: {behavior_key}
行为描述: {behavior_description}
类路径: {class_path}
方法签名: {method_signature}

代码片段:
```java
{malicious_code_snippet}
```

请判断这段代码是否真正实现了"{behavior_key}"行为，输出 JSON：
{
  "match": true 或 false,
  "reason": "中文说明判断理由",
  "actual_behavior": "如果代码做的是其他行为，填写实际行为名；否则留空"
}

判断标准：
- true：代码确实实现了该恶意行为（如 sendTextMessage 实现了短信发送）
- false：代码与该行为无关（如标注 sms_fraud 但代码是 Camera 调用）
- 如果代码是第三方标准库的正常 API（如 OkHttp 的正常网络请求），应判 false
- 如果代码确实包含该 API 但用途合法（如 Google OAuth 用的 Cipher 加密），应判 false

只输出 JSON。
```

### 阶段二流程

1. 读取阶段一的"可疑"列表
2. 4 线程并行调用 qwen3.7-plus
3. 解析 LLM 返回的 JSON
4. `match=false` 的标记为"验证不通过"
5. 记录失败原因和实际行为（如果 LLM 指出了）

### 预估

- 可疑对数：850-1,700（取决于阶段一过滤率）
- 每次调用约 5-15 秒
- 4 并行处理
- 耗时：30-90 分钟
- Token：50-200 万（取决于可疑对数）

## 验证不通过的条件

以下情况判定为"验证不通过"：

| 编号 | 条件 | 来源阶段 |
|------|------|---------|
| E01 | snippet 中未命中任何期望关键词，且 LLM 判定 match=false | 阶段一+二 |
| E02 | snippet 中未命中任何期望关键词，LLM 判定 match=true（规则误报，LLM 确认匹配） | 不算失败 |
| E03 | snippet 过短（< 20 字符），无法判断行为 | 阶段一 |
| ~~E04~~ | ~~class_path 格式异常（如反斜杠路径）~~ | 已移除，不计入验证结果 |
| E05 | behavior_description 为空或含"GLM 分析失败"模板文字 | 阶段一 |
| E06 | LLM 判定代码是第三方标准库的正常 API | 阶段二 |
| E07 | LLM 判定代码用途合法（如 OAuth 加密） | 阶段二 |

注：E02 不算验证不通过（规则过于严格，但 LLM 确认匹配正确）。**E04（class_path 反斜杠）已移除**，不再计入验证结果，不生成输出文件，不影响内容正确性判断。仅包含 E01/E03/E05/E06/E07 的结果才会输出到 output 目录。

## 输出格式

每个验证不通过的 APK 生成一个 JSON 文件：

```json
{
  "apk_sha256": "xxxx...",
  "apk_file": "xxxx.apk",
  "source_dir": "malradar-2",
  "verify_time": "2026-08-24T10:00:00",
  "total_behaviors": 5,
  "total_code_snippets": 7,
  "failed_snippets": [
    {
      "behavior": "sms_fraud",
      "class_path": "Lcom/example/Foo;",
      "method_signature": "bar()",
      "malicious_code_snippet": "...",
      "behavior_description": "...",
      "fail_code": "E01",
      "fail_reason": "snippet 中未包含 sms_fraud 相关 API，LLM 判定代码与短信欺诈无关",
      "llm_actual_behavior": "camera_capture",
      "llm_reason": "代码调用的是 Camera.open() 和 takePicture()，与短信无关"
    }
  ]
}
```

## 执行流程

```
阶段一（规则匹配）
  遍历 3,476 个 _vul_code.json
    → 提取 behavior-code pairs
    → 规则关键词匹配
    → 输出：通过列表 + 可疑列表
  耗时：2-5 分钟，0 token

阶段二（LLM 复核）
  读取可疑列表
    → 4 线程并行调 qwen3.7-plus
    → 解析 LLM 返回
    → match=false 的标记为验证不通过
  耗时：30-90 分钟，50-200 万 token

输出
  验证不通过的结果 → D:\SCA_APK\verify\output\<sha256>_verify_fail.json
  验证统计报告 → D:\SCA_APK\verify\output\verify_summary.json
```

## 统计报告

验证完成后输出 `verify_summary.json`：

```json
{
  "verify_time": "2026-08-24T12:00:00",
  "total_apks": 3476,
  "total_pairs": 17000,
  "stage1_passed": 15300,
  "stage1_suspicious": 1700,
  "stage2_passed": 1500,
  "stage2_failed": 200,
  "overall_pass_rate": "98.8%",
  "fail_by_code": {
    "E01": 150,
    "E03": 10,
    "E04": 35,
    "E05": 5,
    "E06": 30,
    "E07": 5
  },
  "token_consumed": {
    "stage2_input": 1500000,
    "stage2_output": 200000,
    "stage2_total": 1700000
  }
}
```
