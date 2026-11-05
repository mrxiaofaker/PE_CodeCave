# PE CodeCave

一个面向 Windows PE 文件的**代码洞穴检测与结构异常分析工具**，用于授权的恶意软件分析、PE 结构研究和防御性安全验证。

程序可以解析 PE 文件、识别可疑空闲区域、检查节区与熵值异常，并生成控制台、HTML 或 JSON 报告。

> PE CodeCave 提供的是启发式分析结果，不能单独作为文件是否为恶意软件的最终结论。请仅在拥有合法授权的环境中分析样本。

## 功能

- 解析 DOS Header、NT Header、节表、入口点、映像基址和节区权限。
- 计算文件及节区熵值。
- 检测零填充代码洞穴。
- 检测重复模式填充的潜在代码洞穴。
- 检测相邻节区之间的间隙。
- 关联入口点周围的洞穴聚集情况。
- 标记低熵或高熵的可执行节。
- 检测相邻节区熵值突变。
- 检测可写且可执行的节区（RWX）。
- 检测纯虚拟节、异常虚拟/原始大小比例等结构特征。
- 支持单文件分析、目录批量扫描和扩展名过滤。
- 支持控制台摘要、独立 HTML 报告和 JSON 报告。
- HTML 报告包含风险概览、节区信息、洞穴与异常明细，并支持搜索和风险筛选。

## 环境要求

- Windows 10 或 Windows 11
- Visual Studio 2022
- “使用 C++ 的桌面开发”工作负载
- Windows 10/11 SDK
- MSVC v143 工具集

项目当前不依赖第三方运行时库。

## 构建

### 使用 Visual Studio

1. 打开 [PE_CodeCave.vcxproj](./PE_CodeCave.vcxproj)。
2. 选择 `Release` 配置和 `x64` 平台。
3. 执行“生成解决方案”。

默认输出路径：

```text
x64\Release\PE_CodeCave.exe
```

### 使用 MSBuild

在项目根目录打开 Developer PowerShell for VS 2022，然后执行：

```powershell
msbuild .\PE_CodeCave.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64 /m
```

也可以使用 Visual Studio 自带的 MSBuild：

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' `
  '.\PE_CodeCave.vcxproj' `
  /t:Build `
  /p:Configuration=Release `
  /p:Platform=x64 `
  /m
```

> 当前版本可以成功构建，但编译器仍会输出少量类型转换、函数声明和 const 限定符警告，后续可继续清理。

## 使用

启动程序：

```powershell
.\x64\Release\PE_CodeCave.exe
```

程序采用交互式菜单：

```text
1. 分析 PE 文件
2. 批量分析多个文件
3. 配置设置
4. 显示帮助
5. 退出
```

### 单文件分析

选择 `1`，输入目标 PE 文件的完整路径。程序会在控制台显示摘要，并根据配置决定是否生成 HTML 和 JSON 报告。

### 批量分析

选择 `2`，按提示输入目录、是否递归扫描、是否为每个文件生成报告，以及扫描的文件类型。

批量扫描可以选择：

- `EXE`、`DLL`、`SYS`
- 目录中的所有文件
- 自定义扩展名（当前版本仍回退到 `EXE`、`DLL`、`SYS`，该功能待完善）

### 配置设置

配置菜单可以调整详细输出、HTML/JSON 报告开关、报告输出目录、日志级别、熵值阈值和最小洞穴大小等参数。

默认配置：

| 配置项 | 默认值 |
| --- | --- |
| 详细控制台输出 | 开启 |
| JSON 报告 | 关闭 |
| HTML 报告 | 关闭 |
| 报告目录 | 当前目录 |
| 日志级别 | `INFO` |
| 低熵阈值 | `4.0` |
| 最小洞穴大小 | `5` 字节 |
| 最大洞穴大小 | `4096` 字节 |

## 报告

报告默认输出到配置中指定的目录，文件名格式为：

```text
<样本名>_PE_CodeCave_<时间戳>.html
<样本名>_PE_CodeCave_<时间戳>.json
```

JSON 报告使用 `pe-codecave.report.v1` 结构，主要包含：

- 工具和 schema 版本
- 目标文件信息
- 风险分数与风险等级
- 节区信息及节区权限
- 检测到的代码洞穴
- 异常模式及严重性
- 风险评分组成
- 分析建议

## 项目结构

```text
PE_CodeCave/
|-- main.c                     程序入口和交互菜单
|-- PE_CodeCave.vcxproj        Visual Studio 项目
|-- include/
|   |-- common.h               公共常量和结果码
|   `-- types.h                核心数据结构
|-- core/
|   `-- engine.c               分析流程调度
|-- parser/
|   `-- pe_parser.c            PE Header 和节区解析
|-- analyzer/
|   `-- cave_detector.c        代码洞穴检测
|-- detector/
|   `-- anomaly_detector.c     PE 结构和熵值异常检测
|-- reporter/
|   |-- report_generator.c     控制台报告
|   `-- structured_report.c    HTML/JSON 报告
`-- untils/
    `-- file_tils.c            文件读取和目录扫描
```

## 已知限制

- 检测规则属于启发式分析，可能产生误报或漏报。
- 当前只处理 Windows PE 结构，不支持 ELF、Mach-O 等其他可执行格式。
- 部分配置字段已出现在交互菜单中，但部分检测阈值仍由 `include/common.h` 中的常量控制，配置项尚未完全接入所有检测路径。
- 批量扫描的“自定义扩展名”选项尚未完成输入和匹配逻辑，当前会回退到默认 PE 扩展名。
- 批量分析界面的汇总报告选项仍在完善中；当前稳定输出为控制台报告和单文件 HTML/JSON 报告。
- 源文件中的中文字符串主要使用 GBK/CP936 编码。使用 UTF-8 打开时可能出现乱码，编辑和保存时需要注意编码。
- 程序只进行静态文件分析，不执行目标文件，也不进行动态沙箱或运行时行为分析。

## 安全说明

本项目用于授权的安全研究、恶意软件分析和 PE 格式学习。请勿将其用于未经授权的系统、样本或数据。

## 许可证

仓库当前尚未添加 `LICENSE` 文件。在明确许可证之前，请勿默认将本项目视为可自由复制、修改或再分发。
