# FuzzGen4Ghidra 验证记录（2026-11-05）

结论：现有测试不完整。45 个测试全部通过，但补充编译和运行验证复现了下面的问题。本轮只增加验证脚本和记录，没有修改产品代码，也没有覆盖原有未提交改动。

## 实际执行结果

| 验证 | 结果 | 证明范围 |
|---|---|---|
| `PYTHONPATH=python ../.venv/bin/python -m pytest test/ -q` | 45 passed，1 条第三方依赖弃用警告 | 包含真实 angr 加载/扫描，但原 integration 仅断言导出文件存在 |
| 10 种参数场景 × AFL/libFuzzer | 20 次语法编译，13 通过、7 失败 | 失败为 multi-buffer × 2、callback × 2、custom struct × 2、AFL 名称冲突 × 1 |
| 真实动态库 + AFL harness | 4 次实际调用 | basic 正常；scalar-after-buffer、const-buffer、length-mismatch 均出现错误实参 |
| NDK r28，4 ABI × 2 格式 × 3 JNI 模式 | 24 次编译和链接通过 | 使用无 fuzz 参数的最小函数，验证模板/链接；不代表复杂参数正确或设备运行成功 |
| JDK 23 编译全部 6 个 Java 源文件 | 通过 | 使用本地 Ghidra 11.4.3 JAR，未运行 Gradle 打包或 Ghidra UI |
| JNI stub + host ASan | 复现内存越界 | 使用 NDK jni.h，运行生成的原始 stub |
| macOS `/bin/bash` 3.2 运行设备脚本 | 出现数组语法错误，但退出码为 0 | adb 使用本地 mock，没有操作真实设备 |

环境：macOS x86_64，Apple clang 21，Python 3.12，NDK 28.0.12916984。编译矩阵使用 clang/NDK 直接编译；没有验证生成 Makefile 的所有默认构建命令。

## 已复现问题

### 1. P1：第一个 buffer 消耗全部输入，后续标量无法变异

位置：`python/fuzzgen4ghidra_engine/harness.py:28-41`。

签名 `probe(byte *buf, int len, int flags)`，输入为 1 至 32 的非零字节。真实目标输出 `32:0`，即 len=32、flags=0。buffer 先消耗全部数据，随后 consume_bytes 失败被忽略，flags 保持初始化值。fuzzer 看似运行，依赖 flags 的分支却无法探索。需要为后续参数保留输入，明确短输入处理规则。

### 2. P1：const buffer 被当成结构体，长度为 0

位置：`python/fuzzgen4ghidra_engine/params.py:38-53`。

签名 `probe(const unsigned char *buf, int len)` 被恢复为 STRUCT_PTR + 独立 INT。32 字节输入全部进入 256 字节临时结构体缓冲区，len 读取失败；真实目标收到 len=0。应先规范化 const/volatile 和指针空格，再分类并配对。

### 3. P1：长度正则把 option 识别为长度

位置：`python/fuzzgen4ghidra_engine/params.py:35,56-63`。

签名 `probe(byte *buf, int option, int len)`。正则包含未限定边界的 `n`，`option` 被选为长度。目标实际收到 option=32、len=0。必须按完整名称/后缀和关联关系配对，避免一个字符的子串命中。

### 4. P1：多 buffer 的长度配错并生成重定义

位置：`params.py:56-63`、`harness.py:28,40`。

签名 `probe(byte *a, int a_len, byte *b, int b_len)`：两个 buffer 都绑定第一个 a_len，b_len 仍作为独立 int 声明，与自动生成的 `size_t b_len` 冲突。AFL 和 libFuzzer 都编译失败。即使只改掉名字冲突，第一个 buffer 吞掉后续输入的问题仍需解决。

### 5. P1/P2：回调和自定义类型生成未定义 C 类型

位置：`harness.py:172-173`、`engine.py:202` 附近的 `generate_types_header([])`。

`code *cb` 虽被识别为 FUNC_PTR，但函数签名仍保留 `code *`，clang 报 unknown type name 'code'。`parser_ctx *ctx` 同样报未知类型；导出的 types.h 始终没有用户结构定义。两种格式均失败。回调需要合法 C 声明；自定义类型应导出必要定义，或明确拒绝不支持的签名。

### 6. P2：合法参数名与 AFL 内部变量冲突

位置：`templates/afl_harness.c.j2` 中 `target_fn_t target` 和参数声明区域。

单参数 `int target` 导致 redefinition of 'target'。该场景 libFuzzer 可编译、AFL 不可编译。内部变量并未全部使用保留前缀，需要统一生成不冲突的名称。

### 7. P1：JNI stub 自身可产生越界，污染漏洞结论

位置：`templates/jni_stub.h.j2:138-146`。

复现：创建字符串 "abc"，调用 `GetStringUTFRegion`，start=-1、len=1。stub 未检查负下标，直接从 `o->data - 1` 拷贝。ASan 证据见 `jni-asan.log`。这是 harness 支撑代码的错误，不能归因于目标库。

JNI 规定无效索引应触发 StringIndexOutOfBoundsException；stub 至少应阻止越界并维护异常状态。参考：[Oracle JNI GetStringUTFRegion](https://docs.oracle.com/en/java/javase/24/docs/specs/jni/functions.html#getstringutfregion)。

### 8. P1：设备脚本不兼容 macOS 默认 Bash，且可能假成功

位置：`templates/run_on_device.sh.j2:39-45`。

脚本使用关联数组 `declare -A` 和字符串下标。macOS `/bin/bash` 3.2 不支持，复现输出 `libprobe.so: syntax error: invalid arithmetic operator`。本轮模拟 adb 时脚本最终仍返回 0，因此只检查退出码也会漏报。依赖库遍历/去重不能可靠完成；应使用 Bash 3 兼容写法，或启动时明确检查 Bash 版本。

## 尚未覆盖

- Ghidra GUI：菜单上下文、切换项目、预览/保存、失败初始化、引擎重启和取消任务。
- 真实 TCP 客户端交互、并发、多连接共享引擎、断线和超时。现有 protocol 测试仅测试 JSON 构造/解析。
- Android 真机运行、实际 JNI 初始化路径、依赖库加载、长时间 fuzzing；交叉编译通过不能代替这些验证。
- Linux/glibc host、Mach-O 地址模式、PE、ARM Thumb、本地符号与重定位地址边界。
- 生成 Makefile 的实际 AFL++/libFuzzer 默认工具链、扩展打包与安装。

## 重跑

从仓库根目录运行（验证脚本针对本次 macOS 环境，依赖 clang、本地 Ghidra 和 NDK）：

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
export JAVA_HOME=/path/to/jdk-23/Contents/Home
PYTHONPATH=python ../.venv/bin/python -m pytest test/ -q
../.venv/bin/python docs/validation/validation_matrix.py
../.venv/bin/python docs/validation/validation_extra.py
```

可设置 `FUZZGEN_VALIDATION_OUT` 改变临时产物目录；默认 `/private/tmp/fuzzgen-validation-20261105`。脚本是证据采集器，会保留编译失败及崩溃日志；脚本自身退出 0 不表示所有用例通过。矩阵详见 `results.json`。所有目标库均为脚本生成的简单本地测试库，设备启动验证使用 mock adb。
