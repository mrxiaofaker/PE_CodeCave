# PE CodeCave

PE CodeCave 是一个面向 Windows PE 文件的静态代码洞穴检测与结构异常分析工具。项目使用 C 和 Win32/PE 结构解析代码，对可执行文件进行节区、熵值、空闲空间和异常布局检查，并输出控制台、HTML 或 JSON 报告。

项目面向授权安全研究、恶意软件静态分析、PE 格式教学和防御性检测规则验证。

> PE CodeCave 给出的是启发式线索，不是恶意软件判定器。代码洞穴、RWX 节区或高熵数据都可能出现在完全合法的软件中。

## 项目概览

| 项目 | 当前内容 |
| --- | --- |
| 实现语言 | C |
| 目标平台 | Windows 10/11 |
| PE 支持 | PE32 / PE32+ 文件头、节表、入口点、映像基址、节区权限与熵值 |
| 检测对象 | 零填充洞穴、模式填充洞穴、节区间隙、入口点洞穴聚集、节区与熵值异常 |
| 输出 | 控制台摘要、独立 HTML 报告、JSON 报告 |
| 自动化 | 原生 CLI 单文件/批量扫描、递归目录、自定义扩展名、CSV 汇总 |
| 构建方式 | Visual Studio 2022 / MSBuild，Release 使用静态 C 运行时 |
| 样本清单 | 339 条目标记录 + 100 条 Windows 对照记录 |
| 运行时依赖 | 无第三方运行时库 |

## 版本与文章对齐

阿里云先知预览文章暂时引用的是提交 `0727f0d`。该提交会保留为不可变基线标签：

```text
article-0727f0d
```

仓库发布和新增对照实验使用标签：

```text
v1.0.0
```

- 复现文章中的原始基线：`git checkout article-0727f0d`
- 复现新增 CLI、静态发布版和对照实验：`git checkout v1.0.0`
- 文章原始数据：339/339 命中代码洞穴，333/339 达到单文件 150 条上限
- `v1.0.0` 的新对照数据全部使用同一个发布二进制重新生成

文章在审核中暂时无法修改，因此仓库通过 [docs/ARTICLE_ALIGNMENT.md](./docs/ARTICLE_ALIGNMENT.md) 记录版本映射。后续引用时应写 `v1.0.0`，而不是裸提交哈希。

## 检测能力

- 解析 DOS Header、NT Header、Optional Header、节表和节区权限。
- 计算整个文件与每个节区的 Shannon 熵。
- 检测连续 `0x00` 填充形成的代码洞穴。
- 检测重复字节模式形成的潜在代码洞穴。
- 检测相邻节区之间的 RVA 间隙。
- 检测入口点附近洞穴聚集和全局洞穴聚集。
- 检测可写且可执行的节区（RWX）。
- 检测纯虚拟节和异常的虚拟大小/原始大小比例。
- 检测低熵或高熵的可执行节，以及相邻节区熵值突变。
- 支持单文件分析和目录批量扫描。
- 生成可筛选、可打印的 HTML 风险报告。
- 生成带 schema 版本、评分拆解和明细数组的 JSON 报告。

## 运行要求

- Windows 10 或 Windows 11
- x64 系统
- 无需管理员权限
- 发布版不要求安装 Visual Studio 或 VC++ Redistributable

## 下载预编译版

不想安装 Visual Studio 时，可以直接从 [Releases](https://github.com/mrxiaofaker/PE_CodeCave/releases/latest) 下载 `win-x64` 压缩包。解压后即可运行 `PE_CodeCave.exe`。

```powershell
.\PE_CodeCave.exe --version
.\PE_CodeCave.exe --help
```

发布二进制当前未做代码签名，Windows SmartScreen 可能显示未知发布者提示。每个 Release 同时提供 `SHA256SUMS.txt` 供下载后校验。

维护者可以用以下命令重新生成发布包：

```powershell
.\scripts\Build-Release.ps1 -Version 1.0.0
```

## 源码构建要求

- Visual Studio 2022
- “使用 C++ 的桌面开发”工作负载
- Windows 10/11 SDK
- MSVC v143 工具集

## 构建

### Visual Studio

1. 打开 [PE_CodeCave.vcxproj](./PE_CodeCave.vcxproj)。
2. 选择 `Release` 配置和 `x64` 平台。
3. 执行“生成解决方案”。

输出路径：

```text
x64\Release\PE_CodeCave.exe
```

### MSBuild

在 Developer PowerShell for VS 2022 中执行：

```powershell
msbuild .\PE_CodeCave.vcxproj `
  /t:Build `
  /p:Configuration=Release `
  /p:Platform=x64 `
  /m
```

也可以直接调用 Visual Studio 自带的 MSBuild：

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' `
  '.\PE_CodeCave.vcxproj' `
  /t:Build `
  /p:Configuration=Release `
  /p:Platform=x64 `
  /m
```

当前源码可以完成无警告的 `Release|x64` 构建，并使用静态 C 运行时，发布版不要求安装 VC++ Redistributable。

## 命令行用法与参数

程序同时支持原生非交互 CLI 和无参数交互菜单。

```powershell
.\x64\Release\PE_CodeCave.exe --path <file-or-directory> [options]
```

### CLI 参数

| 参数 | 作用 |
| --- | --- |
| `--path <path>` | 必填；输入 PE 文件或目录，也可以把路径作为第一个位置参数 |
| `--recursive` | 目录模式递归扫描子目录 |
| `--extensions <list>` | 自定义扩展名，逗号或分号分隔，默认 `exe,dll,sys`，支持 `*` |
| `--html` | 为每个文件生成 HTML 报告 |
| `--json` | 为每个文件生成 JSON 报告 |
| `--out <directory>` | 报告和批量汇总输出目录，默认 `.` |
| `--quiet` | 隐藏逐文件控制台明细，仍输出最终统计 |
| `--verbose` | 显示逐文件控制台明细，默认开启 |
| `--help`, `-h` | 显示帮助 |
| `--version` | 显示版本 |

目录模式始终在输出目录生成 `batch_summary.csv`。

### 单文件示例

```powershell
.\x64\Release\PE_CodeCave.exe `
  --path .\sample.exe `
  --html `
  --json `
  --out .\reports
```

### 批量示例

```powershell
.\x64\Release\PE_CodeCave.exe `
  --path 'F:\Delta Force\Delta Force' `
  --recursive `
  --extensions exe,dll,sys `
  --json `
  --out .\reports `
  --quiet
```

批量 CSV 字段为：

```text
target_file,analysis_status,report_status,cave_count,anomaly_count,message
```

CLI 退出码：`0` 表示全部成功，`1` 表示存在分析或导出失败，`2` 表示参数或路径错误。

### 交互菜单

不带任何参数启动时仍会进入原交互菜单：

```powershell
.\x64\Release\PE_CodeCave.exe
```

| 选项 | 功能 | 需要输入的参数 |
| --- | --- | --- |
| `1` | 分析单个 PE 文件 | 文件完整路径 |
| `2` | 批量分析目录 | 目录、是否递归、报告选项、扩展名类型 |
| `3` | 修改运行配置 | 详细输出、HTML/JSON 开关、报告目录、阈值等 |
| `4` | 显示帮助 | 无 |
| `5` | 退出 | 确认 `y/n` |

交互单文件分析：

```text
1
F:\samples\target.exe
```

程序会输出 PE 摘要、节区列表、洞穴明细和异常明细。HTML/JSON 报告默认关闭，需要在配置菜单中选择 `3` 后开启。

交互目录分析：

选择 `2` 后依次输入：

1. 待扫描目录。
2. 是否递归扫描子目录。
3. 是否为每个文件生成独立报告。
4. 输入 `1` 扫描 `EXE/DLL/SYS`。
5. 输入 `2` 扫描目录中的所有文件。

交互菜单里的“自定义扩展名”入口仍会回退到 `EXE/DLL/SYS`；自动化场景应使用 `--extensions`，该参数已经走原生 CLI 路径。

## 运行配置

默认配置如下：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| 详细控制台输出 | 开启 | 显示洞穴与异常明细 |
| JSON 报告 | 关闭 | 在报告目录生成 `.json` |
| HTML 报告 | 关闭 | 在报告目录生成 `.html` |
| 报告目录 | `.` | 当前工作目录 |
| 日志级别 | `INFO` | Debug/Info/Warning/Error |
| 低熵阈值 | `4.0` | 低于该值的可执行节被标记 |
| 高熵阈值 | `7.5` | 高于该值的可执行节被标记 |
| 最小洞穴大小 | `5` 字节 | 很小的空洞也会进入候选集合 |
| 最大洞穴大小 | `4096` 字节 | 单条模式洞穴扫描上限 |
| 单文件洞穴上限 | `150` | 达到上限后停止追加 |
| 单文件异常上限 | `50` | 达到上限后停止追加 |

> 配置菜单中的熵值和最小洞穴大小尚未完全接入全部检测路径，部分规则仍由 `include/common.h` 中的常量控制。这个差距会直接影响阈值调整效果。

## 输出报告

报告默认写入配置中的报告目录，命名格式为：

```text
<样本名>_PE_CodeCave_<YYYYMMDD_HHMMSS>.html
<样本名>_PE_CodeCave_<YYYYMMDD_HHMMSS>.json
```

HTML 报告适合人工复核，包含风险概览、节区熵值、洞穴清单、异常清单、处置建议，以及搜索和风险筛选控件。

### JSON 顶层字段

| 字段 | 含义 |
| --- | --- |
| `schema` | 固定为 `pe-codecave.report.v1` |
| `tool` | 工具名称、组件、实现语言和评分模型 |
| `generated_at` | 报告生成时间，ISO 格式 |
| `analysis_time` | Unix 时间戳 |
| `analysis_time_iso` | 分析时间的 ISO 表示 |
| `target` | 文件路径、大小、映像基址、入口点 |
| `summary` | 风险评分、风险等级、洞穴和异常数量、节区统计 |
| `score_breakdown` | 洞穴、异常、节区三个评分分量，以及置信度统计 |
| `cave_types` | 零填充、模式填充、节区间隙和 overlay 的计数 |
| `anomaly_severity` | 低、中、高、严重异常数量 |
| `sections` | 节区 RVA/FOA、大小、权限和熵值 |
| `code_caves` | 每个洞穴的 FOA、RVA、大小、类型、置信度和描述 |
| `anomalies` | 异常模式、严重性、偏移、所属节区和证据描述 |
| `recommendations` | 基于命中的处置建议 |
| `notes` | 静态启发式结果的使用边界 |

### 风险评分解释

综合评分上限为 100，由三部分组成：

```text
risk_score = cave_component + anomaly_component + section_component
```

| 分数范围 | 报告等级 | 含义 |
| --- | --- | --- |
| `80-100` | 严重 / `CRITICAL` | 多个高风险信号叠加，需要优先人工复核 |
| `60-79` | 高危 / `HIGH` | 存在明显可疑结构，但不等同于恶意 |
| `35-59` | 较高 / `ELEVATED` | 需要结合来源、签名和上下文检查 |
| `15-34` | 关注 / `GUARDED` | 有低强度信号，可做基线对比 |
| `0-14` | 低风险 / `LOW` | 当前规则未发现主要静态指标 |

该评分模型尚未使用带标签语料校准，不能直接映射为概率。数量上限、细小空洞计数和节区属性都会显著影响分数。

## 339 个样本的处理方式

仓库不包含 PE 可执行文件本体，也不包含原始 HTML 报告。数据集以清单和来源说明形式保存：

- [samples/manifest.csv](./samples/manifest.csv)：339 条记录，包含 SHA256、文件大小、来源位置、原始报告名和原始报告统计。
- [samples/summary.csv](./samples/summary.csv)：数据集汇总统计。
- [scripts/Build-SampleManifest.ps1](./scripts/Build-SampleManifest.ps1)：从报告重新生成清单和 SHA256。
- [scripts/Run-Dataset.ps1](./scripts/Run-Dataset.ps1)：按清单校验哈希并重新运行分析。

### 数据集快照

清单生成时的统计结果：

| 指标 | 数值 |
| --- | --- |
| 报告记录 | 339 |
| 唯一目标路径 | 339 |
| 文件当时可访问 | 339 |
| SHA256 记录 | 339 |
| 唯一 SHA256 | 336 |
| 来源集合 | 1 |
| 原始报告平均风险分 | 69.30 |
| 原始报告最高风险分 | 98 |
| 原始报告风险等级 | 严重 48、高危 285、较高 6 |
| 报告内洞穴条目总数 | 50,587 |
| 报告内异常条目总数 | 1,057 |

336 个唯一哈希说明 339 条记录中包含少量重复文件副本。洞穴总数是报告条目求和，不是去重后的真实洞穴数量；单文件 150 条上限会使总数偏低或在高风险样本上饱和。

### 数据来源

当前 339 个唯一目标路径全部来自本机一套授权的 Delta Force 安装目录：

```text
F:\Delta Force\Delta Force
```

这不是 339 个恶意软件家族，也不是公开基准数据集。它更像一次针对真实大型 Windows 软件目录的静态扫描语料，适合做回归测试、误报分析和规则调参，但不能单独证明检测准确率。

清单中的 `target_path` 是生成时的绝对路径，外部复核者需要准备相同版本的软件，或按 SHA256 和 `source_location` 自行定位对应文件。仓库只记录哈希和来源，不分发受版权保护的可执行文件。

### 重新生成清单

```powershell
.\scripts\Build-SampleManifest.ps1
```

如果只解析报告、不重新计算哈希：

```powershell
.\scripts\Build-SampleManifest.ps1 -NoHash
```

### 一键复现

只校验 339 个文件的 SHA256：

```powershell
.\scripts\Run-Dataset.ps1 -VerifyOnly
```

先跑前 10 条：

```powershell
.\scripts\Run-Dataset.ps1 -Limit 10
```

运行完整清单：

```powershell
.\scripts\Run-Dataset.ps1
```

脚本输出：

```text
artifacts\reproduction\run_results.csv
artifacts\reproduction\logs\PE-0001.log
artifacts\reproduction\reports\*.json
...
```

复现脚本先校验 SHA256，再调用原生 CLI 的 `--path`、`--json`、`--out` 和 `--quiet` 参数重新分析，生成 JSON 报告并保存进程输出。

## Windows 系统对照语料

为了判断“代码洞穴命中”是否真的具有区分度，`v1.0.0` 增加了 100 个不同来源的微软签名系统 PE：

- [control-manifest.csv](./samples/control-manifest.csv)：50 个 `System32` x64 文件和 50 个 `SysWOW64` x86 文件。
- [v1.0.0-comparison.csv](./samples/v1.0.0-comparison.csv)：439 个文件的逐样本结果。
- [comparison.md](./samples/comparison.md)：按类别汇总的对比表。
- [Select-ControlCorpus.ps1](./scripts/Select-ControlCorpus.ps1)：可重复的对照语料选择脚本。
- [Build-CorpusComparison.ps1](./scripts/Build-CorpusComparison.ps1)：使用同一 `v1.0.0` 二进制重跑并生成对比结果。

对照语料固定筛选条件：系统顶层 `EXE/DLL`、64 KB–32 MB、有效 Microsoft Authenticode 签名、按文件名排序，每个目录取 50 个。仓库只保存哈希和元数据，不复制 Windows 二进制。

### 按类别对比

以下结果全部由 `v1.0.0` 发布二进制生成，439 个样本均成功分析：

| 类别 | 样本数 | 唯一哈希 | 平均风险分 | 中位风险分 | 平均洞穴数 | 中位洞穴数 | 达到 150 上限 | 平均异常数 | 平均 RWX 节区 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Delta Force 安装目录 | 339 | 336 | 69.29 | 66 | 149.22 | 150 | 98.23% | 3.12 | 0 |
| Windows System32 (x64) | 50 | 50 | 85.58 | 87 | 150.00 | 150 | 100.00% | 7.56 | 0 |
| Windows SysWOW64 (x86) | 50 | 50 | 71.16 | 70 | 147.42 | 150 | 98.00% | 2.42 | 0 |
| Windows 对照组合计 | 100 | 100 | 78.37 | 80 | 148.71 | 150 | 99.00% | 4.99 | 0 |

### 这组对照证明了什么

这不是“系统文件也有恶意行为”的证据。相反，它证明了当前检测定义缺少指令边界和语义验证：

- Windows 对照组的平均风险分和洞穴数量都不低于 Delta Force 目标组。
- Microsoft 签名的 `System32` 组 50/50 达到 150 条上限，说明风险分对“小空洞数量”高度敏感。
- 5 字节门限会把函数对齐、跳转表、资源填充和指令内部字节都算成候选洞穴。
- 当前实现没有集成 Capstone、反汇编、指令边界校验、基本块恢复或控制流可达性证明。
- 因此风险分应被解释为“候选空洞密度”，不能解释为“注入可能性”或“恶意概率”。

这正是项目比单纯重复字节匹配更有价值的地方：它没有只声称发现洞穴，而是用不同来源的对照语料量化了这个盲区。

## 误报根因与已知局限

这是静态结构分析工具，命中的是“可疑布局”，不是可达的恶意行为。以下因素是最主要的误报来源：

1. **编译器和对齐填充**：代码节中连续的 `0x00` 或短空洞通常来自函数对齐、跳转表和链接器布局。默认最小洞穴只有 5 字节，因此普通程序也会产生大量候选。
2. **重复模式不等于代码**：模式填充可能来自常量数组、资源块、零初始化数据、调试信息和合法编码表。重复字节无法证明该区域可执行或可到达。
3. **节区间隙来自 PE 映射规则**：RVA 对齐、Raw 对齐、BSS 节和手工节表都可能产生间隙。间隙存在不代表加载器会把它当作可执行代码。
4. **熵值不是恶意性指标**：高熵可来自压缩、加密、资源、纹理和受保护程序；低熵可来自稀疏代码节、资源和大量未初始化空间。
5. **RWX 节区可能是合法设计**：JIT、脚本运行时、解包器、模拟器和部分保护软件会使用可写可执行页。权限异常需要结合调用路径和运行时行为判断。
6. **洞穴聚集可能来自正常布局**：入口点附近出现多个小空洞，可能只是函数边界对齐；当前规则没有验证控制流是否能到达这些空洞。
7. **150 条上限导致饱和**：洞穴数量达到 150 后停止追加，评分仍按上限计数。大文件可能因此得到相似的高分，掩盖真实数量差异。
8. **评分模型未校准**：三个分量的权重来自人工规则，没有经过带标签数据集训练、ROC 分析或置信区间评估，不能当作概率。
9. **没有指令边界或控制流验证**：工具未集成 Capstone，不反汇编指令、不验证 x86/x64 指令边界、不恢复基本块，也不证明洞穴可到达。字节窗口与真实指令级空洞可能完全不同。
10. **数据集有对照但仍无标签**：339 条目标记录和 100 条系统对照记录可以展示分布差异，但没有恶意/良性标签、家族标签或人工标注的真实洞穴边界，不能计算准确率、召回率或正式误报率。
11. **配置与实现存在差距**：部分菜单配置尚未接入全部检测路径，修改阈值后的行为可能与界面显示不完全一致。
12. **交互批量菜单仍有占位项**：自定义扩展名和交互汇总报告尚未完全接入；CLI 的 `--extensions`、`--recursive` 和 `batch_summary.csv` 已可用。
13. **路径长度受 `MAX_PATH` 限制**：超长路径和复杂目录树当前不能可靠处理。
14. **仅支持 Windows PE**：不支持 ELF、Mach-O、Java、.NET 托管语义分析或动态沙箱行为。

### 如何降低误报

- 将 `min_cave_size` 从 5 字节提高到 16、32 或 64 字节，并比较结果。
- 排除 `.text` 中由对齐产生的小空洞，优先审核更大、连续且可执行区域中的洞穴。
- 为常见编译器、运行时和商业软件建立可信基线，按节区名称、熵值和权限差异比较。
- 将洞穴 RVA 映射到函数、交叉引用和指令流，确认是否可达。
- 结合数字签名、来源路径、版本信息、导入表、沙箱遥测和威胁情报。
- 对评分进行分层统计，分别报告原始候选数量、截断前数量和去重后的高置信度数量。

## 项目结构

```text
PE_CodeCave/
|-- main.c                      程序入口和交互菜单
|-- cli.c                       原生 CLI、批量调度和 CSV 汇总
|-- PE_CodeCave.vcxproj         Visual Studio 项目
|-- include/
|   |-- common.h                公共常量、结果码和上限
|   `-- types.h                 分析数据结构
|-- core/
|   `-- engine.c                分析流程调度
|-- parser/
|   `-- pe_parser.c             PE Header 与节表解析
|-- analyzer/
|   `-- cave_detector.c         洞穴检测和置信度计算
|-- detector/
|   `-- anomaly_detector.c      节区、熵值和聚集异常
|-- reporter/
|   |-- report_generator.c      控制台报告
|   `-- structured_report.c     HTML/JSON 报告
|-- untils/
|   `-- file_tils.c             文件读取和目录扫描
|-- scripts/
|   |-- Build-SampleManifest.ps1
|   |-- Select-ControlCorpus.ps1
|   |-- Build-CorpusComparison.ps1
|   |-- Build-Release.ps1
|   `-- Run-Dataset.ps1
|-- docs/
|   `-- ARTICLE_ALIGNMENT.md
`-- samples/
    |-- manifest.csv
    |-- control-manifest.csv
    |-- v1.0.0-comparison.csv
    |-- v1.0.0-summary.csv
    `-- comparison.md
```

## 安全与合规

- 仅分析你拥有或已获得授权检查的文件。
- 仓库不保存样本可执行文件、用户目录、凭据或网络流量。
- 清单中的绝对路径用于说明来源，但在公开分享前仍应检查是否符合你的隐私和合规要求。
- 静态扫描结果不能代替数字签名验证、沙箱运行、事件响应或司法取证流程。

## License

本项目使用 [MIT License](./LICENSE)。
