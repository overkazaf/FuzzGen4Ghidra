# FuzzGen4Ghidra

**Automatic fuzzing harness generation for Ghidra, powered by angr.**

[English](#english) | [中文](#中文)

---

## English

FuzzGen4Ghidra is a Ghidra extension that automatically generates AFL++ and libFuzzer fuzzing harnesses for binary functions. It combines Ghidra's decompiler for type recovery with angr's binary analysis for target scoring, producing ready-to-compile C harness code.

### Features

- **Target Scoring** — Scores every function in the binary on 4 axes: complexity, input surface, dangerous calls, and feasibility
- **Parameter Recovery** — Extracts parameter types from Ghidra's decompiler (buffer, int, struct pointer, function pointer)
- **Harness Generation** — Generates complete C harness code with input deserialization, `dlopen`/`dlsym` target loading, and a Makefile
- **Dual Format** — Supports both AFL++ (file-based) and libFuzzer (`LLVMFuzzerTestOneInput`) harness styles
- **Preview & Export** — In-Ghidra preview dialog with syntax highlighting, format switching, and save-to-directory

### Architecture

```
┌──────────────────────────┐         ┌──────────────────────────┐
│     Java Plugin          │         │     Python Engine         │
│     (Ghidra Extension)   │         │     (angr + Jinja2)      │
│                          │         │                          │
│  FuzzGen4GhidraPlugin    │  JSON   │  server.py               │
│  GenerateHarnessAction ──┼──line───┼─ engine.py (FuzzGenEngine)│
│  ScanTargetsAction       │  TCP    │  scorer.py (4-axis)      │
│  HarnessPreviewDialog    │ :13371  │  params.py (type recovery)│
│  EngineProtocol          │         │  harness.py (Jinja2)     │
│  EngineManager           │         │  protocol.py             │
└──────────────────────────┘         └──────────────────────────┘
```

### Pipeline

```
Load Binary → Scan & Score → Recover Params → Generate Harness
     │              │               │                 │
  angr.Project   CFGFast +       Ghidra          Jinja2 C
  auto_load=F    4-axis score    decompiler       templates
```

| Step | What happens |
|------|-------------|
| **1. Load** | Ghidra opens a binary; the plugin sends its path to the Python engine via TCP |
| **2. Scan** | angr builds a CFG, the scorer rates each function by complexity, danger, input surface, and feasibility |
| **3. Params** | Ghidra's decompiler extracts function signatures; the engine classifies each parameter (buffer, int, struct_ptr, func_ptr) and pairs buffer+length params |
| **4. Generate** | Jinja2 renders a complete C harness with input deserialization, a Makefile, a types header, and a seed corpus |

### Screenshots

<!-- Replace with real screenshots after installing in Ghidra -->

| Harness Preview | Scan Results |
|:---:|:---:|
| ![harness-preview](docs/images/harness-preview.png) | ![scan-results](docs/images/scan-results.png) |

### Requirements

- **Ghidra** 11.0+ (tested with 11.4.3)
- **Java** 17+ (JDK 23 recommended)
- **Python** 3.10+ with:
  - `angr` 9.2+
  - `jinja2`
- **Gradle** 8.x (uses Ghidra's `buildExtension.gradle`)

### Installation

#### 1. Build the extension

```bash
cd FuzzGen4Ghidra

JAVA_HOME=/path/to/jdk \
  gradle buildExtension \
  -PGHIDRA_INSTALL_DIR=/path/to/ghidra_11.4.3_PUBLIC
```

This produces `dist/ghidra_*_FuzzGen4Ghidra.zip`.

#### 2. Install in Ghidra

1. Open Ghidra → **File** → **Install Extensions**
2. Click the **+** button, select the `.zip` file
3. Restart Ghidra
4. In CodeBrowser: **File** → **Configure** → Check **FuzzGen4Ghidra**

#### 3. Set up Python environment

```bash
# Create a venv with angr (recommended: in the parent directory)
python3 -m venv .venv
source .venv/bin/activate
pip install angr jinja2
```

The plugin automatically locates `.venv/bin/python3` by searching parent directories.

### Usage

#### Generate a harness for a specific function

1. Open a binary in Ghidra's CodeBrowser
2. Navigate to the target function in the Listing or Decompiler view
3. **Right-click** → **FuzzGen4Ghidra** → **Generate Fuzz Harness**
4. The Preview dialog opens with the generated C code
5. Switch between AFL++ / libFuzzer format using the dropdown
6. Click **Save to Directory** to export harness + Makefile + types.h + seed

#### Scan all functions for fuzz targets

1. Menu bar → **FuzzGen4Ghidra** → **Scan Fuzz Targets**
2. The engine scores every non-trivial function and returns a ranked list
3. Top targets show their score, block count, and reasons (dangerous calls, buffer params, etc.)

### Quick Start Walkthrough

A complete step-by-step guide from installation to fuzzing.

#### Step 1: Build and install the extension

```bash
# Build (replace paths with your actual paths)
cd FuzzGen4Ghidra
JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-23.jdk/Contents/Home \
  gradle buildExtension \
  -PGHIDRA_INSTALL_DIR=$HOME/ghidra_11.4.3_PUBLIC

# The zip is now in dist/
ls dist/ghidra_*_FuzzGen4Ghidra.zip
```

#### Step 2: Install in Ghidra

1. Launch Ghidra (run `ghidraRun` from the Ghidra install directory)
2. In the **Project Window**, go to **File → Install Extensions...**
3. Click the green **+** button in the top-right corner
4. Navigate to and select `dist/ghidra_*_FuzzGen4Ghidra.zip`
5. You should see **FuzzGen4Ghidra** appear in the extensions list with a checkbox
6. Click **OK**, then **restart Ghidra** when prompted

#### Step 3: Set up the Python engine environment

```bash
# Create a venv in the FuzzGen4Ghidra directory (or its parent)
cd FuzzGen4Ghidra
python3 -m venv .venv
source .venv/bin/activate
pip install angr jinja2
```

The Java plugin automatically searches for `.venv/bin/python3` starting from the project directory and walking up parent directories.

#### Step 4: Import a binary and enable the plugin

1. In the Ghidra Project Window, go to **File → Import File...**
2. Select a binary to analyze (e.g., a shared library like `libparser.so` or an ELF executable)
3. Accept the default import options and click **OK**
4. Double-click the imported file to open it in **CodeBrowser**
5. When prompted "Analyze now?", click **Yes** and accept the default analyzers — this runs Ghidra's auto-analysis including the decompiler
6. If the plugin is not yet enabled: go to **File → Configure...**, find the **FuzzGen4Ghidra** section, and check the box to enable it

After enabling, two new features appear:
- **Right-click context menu** → "FuzzGen4Ghidra" → "Generate Fuzz Harness"
- **Menu bar** → "FuzzGen4Ghidra" → "Scan Fuzz Targets"

#### Step 5: Scan for fuzz targets

1. In CodeBrowser, go to the menu bar: **FuzzGen4Ghidra → Scan Fuzz Targets**
2. The plugin starts the Python engine automatically (first run may take a few seconds)
3. A progress dialog shows the engine analyzing each function via angr's CFG
4. When complete, a results table appears showing the top-20 fuzz targets ranked by score
5. Each row shows: function name, address, overall score, block count, and scoring reasons

Use this to identify the best functions to fuzz — look for high scores with dangerous calls (`memcpy`, `strcpy`, etc.) and buffer parameters.

#### Step 6: Generate a fuzz harness

1. In the **Listing** or **Decompiler** view, click on the function you want to fuzz
2. **Right-click → FuzzGen4Ghidra → Generate Fuzz Harness**
3. The **Harness Preview** dialog opens with the generated C source code
4. Use the **Format** dropdown at the top to switch between:
   - **afl** — Generates a `main()` that reads from a file (for AFL++)
   - **libfuzzer** — Generates `LLVMFuzzerTestOneInput()` (for libFuzzer/LLVM)
5. Click **Copy to Clipboard** to copy the code, or
6. Click **Save to Directory...** to export all files to a folder:
   - `harness_<funcname>.c` — The harness source code
   - `types.h` — Type definitions for the target's parameters
   - `Makefile` — Ready-to-use build file for AFL++ or libFuzzer
   - `seeds/seed_000` — Initial seed corpus file

#### Step 7: Compile and run the fuzzer

```bash
cd output_dir/

# For AFL++:
make           # Compiles with afl-gcc and AddressSanitizer
make fuzz      # Starts afl-fuzz with the generated seed corpus

# For libFuzzer:
# (switch format to "libfuzzer" in the preview dialog and re-save)
make           # Compiles with clang -fsanitize=fuzzer,address
make fuzz      # Starts the libFuzzer binary
```

#### FAQ & Troubleshooting

**Q: "Failed to load binary: No module named 'angr'"**

The plugin found a Python interpreter but it doesn't have angr installed. Two solutions:

1. **Set `FUZZGEN_PYTHON` env var** (recommended): point it to the correct venv Python before launching Ghidra:
   ```bash
   export FUZZGEN_PYTHON="/path/to/your/.venv/bin/python3"
   /path/to/ghidra/ghidraRun
   ```
2. **Start the engine manually** in a terminal — the plugin will connect to it automatically:
   ```bash
   cd FuzzGen4Ghidra
   PYTHONPATH=python /path/to/.venv/bin/python3 -m fuzzgen4ghidra_engine -v
   # Then use the plugin in Ghidra as normal
   ```

**Q: "Binary not loaded — call init first"**

You triggered Scan from the **Project Window** instead of **CodeBrowser**. Double-click the binary to open it in CodeBrowser first, then use the plugin from there.

**Q: "Address already in use" when starting the engine manually**

A previous engine process is still running on port 13371. Kill it first:
```bash
lsof -ti :13371 | xargs kill
```

**Q: libFuzzer harness fails to link: `libclang_rt.fuzzer_osx.a not found`**

Apple's Xcode Clang doesn't include the libFuzzer runtime. Install LLVM via Homebrew:
```bash
brew install llvm
/opt/homebrew/opt/llvm/bin/clang -fsanitize=fuzzer,address -o harness harness.c -ldl
```

**Q: AFL harness fails: `afl-gcc: No such file or directory`**

AFL++ is not installed. Install it:
```bash
brew install aflplusplus
```
Or switch to libFuzzer format in the preview dialog (no AFL++ needed, just LLVM clang).

**Q: Harness compiles but crashes immediately with `dlopen` error**

The target library must be in the same directory as the harness (or in a path `dlopen` can find). Copy it:
```bash
cp /path/to/target.so ./   # same directory as the harness
```

| Other Problems | Solution |
|---------|----------|
| Engine takes a long time | angr's CFG analysis is CPU-intensive; large binaries take longer |
| No functions found in scan | The binary may be stripped or have no exported functions; try a shared library |
| "Generate Fuzz Harness" is greyed out | Make sure your cursor is positioned inside a function in the Listing/Decompiler view |

### Demo: Generating a harness

Given a function `parse_packet(const uint8_t *buf, int len)` that calls `memcpy`:

**Generated AFL++ harness (abbreviated):**

```c
/*
 * AFL++ fuzzing harness for parse_packet
 * Generated by FuzzGen4Ghidra
 * Target: libparser.so @ 0x401000
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include "types.h"

typedef int (*target_fn_t)(byte * buf, int len);

static int consume_bytes(const uint8_t *data, size_t data_len,
                        size_t *offset, void *out, size_t n) {
    if (*offset + n > data_len) return -1;
    memcpy(out, data + *offset, n);
    *offset += n;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    /* ... read input into data buffer ... */

    void *lib = dlopen("./libparser.so", RTLD_LAZY);
    target_fn_t target = (target_fn_t)dlsym(lib, "parse_packet");

    size_t offset = 0;

    /* buf (buffer) */
    size_t buf_len = (data_len > offset) ? data_len - offset : 0;
    uint8_t *buf = (uint8_t *)(data + offset);

    target((byte *)buf, (int)buf_len);

    free(data);
    dlclose(lib);
    return 0;
}
```

**Then compile and fuzz:**

```bash
cd output_dir/
make           # builds with afl-gcc + ASan
make fuzz      # starts afl-fuzz with the seed corpus
```

### Target Scoring

Each function is scored on 4 weighted axes (0-100 each):

| Axis | Weight | What it measures |
|------|--------|-----------------|
| **Complexity** | 25% | Number of basic blocks (more blocks = more paths to explore) |
| **Input Surface** | 30% | Buffer parameters, calls to `read`/`recv`/`fgets`, parameter count |
| **Danger** | 25% | Calls to `memcpy`, `strcpy`, `sprintf`, `malloc`, `free`, etc. |
| **Feasibility** | 20% | Exported symbol, has parameters, reachable call depth |

### Running the engine standalone

The Python engine can be started independently for testing:

```bash
cd FuzzGen4Ghidra
PYTHONPATH=python python -m fuzzgen4ghidra_engine -v
# Listening on 127.0.0.1:13371
```

Send JSON commands via TCP:

```bash
echo '{"type":"init","params":{"binary_path":"/path/to/binary"}}' | nc 127.0.0.1 13371
```

### Tests

```bash
# Unit tests (no angr required)
PYTHONPATH=python python -m pytest test/ -v --ignore=test/test_integration.py

# Full suite including integration test (requires angr venv)
PYTHONPATH=python .venv/bin/python3 -m pytest test/ -v
```

25 tests covering protocol, models, scorer, params, harness generation, engine, and end-to-end integration.

### Project Structure

```
FuzzGen4Ghidra/
├── src/main/java/fuzzgen4ghidra/
│   ├── FuzzGen4GhidraPlugin.java      # Plugin entry point
│   ├── actions/
│   │   ├── GenerateHarnessAction.java  # Right-click → generate
│   │   └── ScanTargetsAction.java      # Menu → scan all
│   ├── engine/
│   │   ├── EngineProtocol.java         # Gson Command/Response
│   │   └── EngineManager.java          # Process + TCP management
│   └── ui/
│       └── HarnessPreviewDialog.java   # Code preview + export
├── python/fuzzgen4ghidra_engine/
│   ├── protocol.py       # JSON-line Command/Response
│   ├── models.py         # FuzzTarget, ParamInfo, ParamType
│   ├── scorer.py         # 4-axis fuzzability scoring
│   ├── params.py         # Ghidra signature → ParamInfo
│   ├── harness.py        # Jinja2 C code generation
│   ├── engine.py         # FuzzGenEngine orchestrator
│   ├── server.py         # TCP server on port 13371
│   └── templates/
│       ├── afl_harness.c.j2
│       ├── libfuzzer_harness.c.j2
│       ├── types.h.j2
│       └── Makefile.j2
├── test/                 # 25 tests
├── build.gradle
└── extension.properties
```

### License

Apache 2.0

---

## 中文

FuzzGen4Ghidra 是一个 Ghidra 扩展插件，能够自动为二进制函数生成 AFL++ 和 libFuzzer 的 fuzzing harness。它结合 Ghidra 反编译器的类型恢复能力和 angr 的二进制分析能力，生成可直接编译的 C 语言 harness 代码。

### 功能特性

- **目标评分** — 对二进制中的每个函数从 4 个维度评分：复杂度、输入面、危险调用、可行性
- **参数恢复** — 从 Ghidra 反编译器提取参数类型（buffer、int、结构体指针、函数指针）
- **Harness 生成** — 生成完整的 C harness 代码，包含输入反序列化、`dlopen`/`dlsym` 目标加载和 Makefile
- **双格式支持** — 同时支持 AFL++（基于文件）和 libFuzzer（`LLVMFuzzerTestOneInput`）两种 harness 风格
- **预览与导出** — Ghidra 内置预览对话框，支持语法高亮、格式切换、一键保存到目录

### 架构

插件采用 Java + Python 双进程架构，通过 JSON-line TCP 协议通信（端口 13371），与 [Ponce4Ghidra](https://github.com/user/Ponce4Ghidra) 同一模式：

- **Java 侧**（Ghidra 插件）：负责 UI 交互、反编译器调用、参数提取
- **Python 侧**（angr 引擎）：负责 CFG 分析、目标评分、harness 代码生成

### 评分机制

每个函数按 4 个加权维度评分（各 0-100 分）：

| 维度 | 权重 | 含义 |
|------|------|------|
| **复杂度** | 25% | 基本块数量（越多 = 越多路径可探索） |
| **输入面** | 30% | 是否有 buffer 参数、是否调用 `read`/`recv`/`fgets`、参数数量 |
| **危险度** | 25% | 是否调用 `memcpy`、`strcpy`、`sprintf`、`malloc`、`free` 等 |
| **可行性** | 20% | 是否为导出符号、是否有参数、调用深度 |

### 安装

#### 1. 编译扩展

```bash
cd FuzzGen4Ghidra

JAVA_HOME=/path/to/jdk \
  gradle buildExtension \
  -PGHIDRA_INSTALL_DIR=/path/to/ghidra
```

产出：`dist/ghidra_*_FuzzGen4Ghidra.zip`

#### 2. 安装到 Ghidra

1. 打开 Ghidra → **File** → **Install Extensions**
2. 点击 **+** 按钮，选择 `.zip` 文件
3. 重启 Ghidra
4. 在 CodeBrowser 中：**File** → **Configure** → 勾选 **FuzzGen4Ghidra**

#### 3. 配置 Python 环境

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install angr jinja2
```

插件会自动在父目录中查找 `.venv/bin/python3`。

### 使用方法

#### 为指定函数生成 harness

1. 在 Ghidra CodeBrowser 中打开二进制文件
2. 在 Listing 或 Decompiler 视图中定位到目标函数
3. **右键** → **FuzzGen4Ghidra** → **Generate Fuzz Harness**
4. 预览对话框中查看生成的 C 代码
5. 用下拉框切换 AFL++ / libFuzzer 格式
6. 点击 **Save to Directory** 导出 harness + Makefile + types.h + 种子文件

#### 扫描所有函数的 fuzz 目标

1. 菜单栏 → **FuzzGen4Ghidra** → **Scan Fuzz Targets**
2. 引擎对每个非平凡函数评分，返回排序列表
3. 查看每个目标的评分、基本块数、评分原因

### 完整使用教程

从安装到 fuzz 的每一步详细指引。

#### 第 1 步：编译并安装扩展

```bash
# 编译（替换为你实际的路径）
cd FuzzGen4Ghidra
JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-23.jdk/Contents/Home \
  gradle buildExtension \
  -PGHIDRA_INSTALL_DIR=$HOME/ghidra_11.4.3_PUBLIC

# zip 文件生成在 dist/ 目录
ls dist/ghidra_*_FuzzGen4Ghidra.zip
```

#### 第 2 步：安装到 Ghidra

1. 启动 Ghidra（在 Ghidra 安装目录运行 `ghidraRun`）
2. 在**项目窗口**中，打开 **File → Install Extensions...**
3. 点击右上角绿色的 **+** 按钮
4. 选择 `dist/ghidra_*_FuzzGen4Ghidra.zip`
5. 列表中出现 **FuzzGen4Ghidra** 并勾选
6. 点击 **OK**，根据提示**重启 Ghidra**

#### 第 3 步：配置 Python 引擎环境

```bash
# 在 FuzzGen4Ghidra 目录或其父目录创建 venv
cd FuzzGen4Ghidra
python3 -m venv .venv
source .venv/bin/activate
pip install angr jinja2
```

Java 插件会自动在项目目录及父目录中查找 `.venv/bin/python3`。

#### 第 4 步：导入二进制文件并启用插件

1. 在 Ghidra 项目窗口，**File → Import File...**
2. 选择要分析的二进制文件（如共享库 `libparser.so` 或 ELF 可执行文件）
3. 使用默认导入选项，点击 **OK**
4. 双击导入的文件，在 **CodeBrowser** 中打开
5. 提示 "Analyze now?" 时点击 **Yes**，接受默认分析器 — Ghidra 会运行自动分析（包括反编译）
6. 如果插件未启用：**File → Configure...**，找到 **FuzzGen4Ghidra** 并勾选

启用后会看到两个新功能入口：
- **右键菜单** → "FuzzGen4Ghidra" → "Generate Fuzz Harness"
- **菜单栏** → "FuzzGen4Ghidra" → "Scan Fuzz Targets"

#### 第 5 步：扫描 fuzz 目标

1. 在 CodeBrowser 菜单栏：**FuzzGen4Ghidra → Scan Fuzz Targets**
2. 插件自动启动 Python 引擎（首次运行可能需要几秒）
3. 进度对话框显示 angr CFG 分析进度
4. 完成后弹出结果表格，展示按评分排序的 Top-20 目标函数
5. 每行包含：函数名、地址、综合评分、基本块数、评分原因

利用此结果找到最适合 fuzz 的函数 — 关注高分且包含危险调用（`memcpy`、`strcpy` 等）和 buffer 参数的函数。

#### 第 6 步：生成 fuzz harness

1. 在 **Listing** 或 **Decompiler** 视图中，点击目标函数
2. **右键 → FuzzGen4Ghidra → Generate Fuzz Harness**
3. 弹出 **Harness Preview** 对话框，展示生成的 C 源码
4. 用顶部 **Format** 下拉框切换格式：
   - **afl** — 生成 `main()` 函数从文件读取输入（适用 AFL++）
   - **libfuzzer** — 生成 `LLVMFuzzerTestOneInput()`（适用 libFuzzer/LLVM）
5. 点击 **Copy to Clipboard** 复制代码，或
6. 点击 **Save to Directory...** 将全部文件导出到一个目录：
   - `harness_<函数名>.c` — harness 源码
   - `types.h` — 目标函数参数的类型定义
   - `Makefile` — 可直接使用的构建文件
   - `seeds/seed_000` — 初始种子语料文件

#### 第 7 步：编译并运行 fuzzer

```bash
cd output_dir/

# AFL++ 模式：
make           # 用 afl-gcc + ASan 编译
make fuzz      # 启动 afl-fuzz，使用生成的种子语料

# libFuzzer 模式：
# （在预览对话框中切换为 "libfuzzer" 格式，重新保存）
make           # 用 clang -fsanitize=fuzzer,address 编译
make fuzz      # 启动 libFuzzer
```

#### 常见问题（FAQ）

**Q: "Failed to load binary: No module named 'angr'"**

插件找到了 Python 解释器，但该 Python 没有安装 angr。两种解决方案：

1. **设置 `FUZZGEN_PYTHON` 环境变量**（推荐）：在启动 Ghidra 前指定正确的 venv Python：
   ```bash
   export FUZZGEN_PYTHON="/path/to/.venv/bin/python3"
   /path/to/ghidra/ghidraRun
   ```
2. **手动启动引擎** — 插件会自动连接到已运行的引擎：
   ```bash
   cd FuzzGen4Ghidra
   PYTHONPATH=python /path/to/.venv/bin/python3 -m fuzzgen4ghidra_engine -v
   # 然后在 Ghidra 中正常使用插件
   ```

**Q: "Binary not loaded — call init first"**

你在**项目窗口**而不是 **CodeBrowser** 中触发了扫描。先双击二进制文件在 CodeBrowser 中打开，然后再使用插件。

**Q: 手动启动引擎时报 "Address already in use"**

端口 13371 被旧进程占用，先杀掉：
```bash
lsof -ti :13371 | xargs kill
```

**Q: libFuzzer harness 链接失败：`libclang_rt.fuzzer_osx.a not found`**

macOS 自带的 Apple Clang 不包含 libFuzzer 运行时。需要安装 Homebrew LLVM：
```bash
brew install llvm
/opt/homebrew/opt/llvm/bin/clang -fsanitize=fuzzer,address -o harness harness.c -ldl
```

**Q: AFL harness 编译失败：`afl-gcc: No such file or directory`**

未安装 AFL++。安装方法：
```bash
brew install aflplusplus
```
或在预览对话框中切换为 libFuzzer 格式（只需 LLVM clang，无需 AFL++）。

**Q: Harness 编译成功但运行时 `dlopen` 报错**

目标库必须在 harness 同目录下（或在 `dlopen` 可查找的路径中）：
```bash
cp /path/to/target.so ./   # 复制到 harness 同目录
```

| 其他问题 | 解决方案 |
|---------|----------|
| 引擎启动很慢 | angr 的 CFG 分析是 CPU 密集型的，大型二进制文件需要更多时间 |
| 扫描未发现函数 | 二进制可能被 strip 了或没有导出函数，尝试使用共享库 |
| "Generate Fuzz Harness" 灰色不可点 | 确保光标在 Listing/Decompiler 视图中的某个函数内部 |

### 演示：从生成到 fuzzing

```bash
# 1. 在 Ghidra 中右键 parse_packet → Generate Fuzz Harness
#    → Save to Directory → 选择 output/

# 2. 编译并开始 fuzz
cd output/
make           # 用 afl-gcc + ASan 编译
make fuzz      # 启动 afl-fuzz，使用自动生成的种子语料

# 3. 或者用 libFuzzer
# 在预览对话框中切换格式为 libfuzzer，重新保存
make           # 用 clang -fsanitize=fuzzer 编译
make fuzz      # 启动 libFuzzer
```

### 测试

```bash
# 单元测试（不需要 angr）
PYTHONPATH=python python -m pytest test/ -v --ignore=test/test_integration.py

# 完整测试（需要 angr venv）
PYTHONPATH=python .venv/bin/python3 -m pytest test/ -v
# 25 passed ✓
```

### 许可证

Apache 2.0
