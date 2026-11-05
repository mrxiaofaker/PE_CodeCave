# v1.0.0 Corpus Comparison

Measured with the `v1.0.0` release binary. Sample bodies are not stored in this repository.

| Category | Samples | Mean risk | Median risk | Mean caves | Median caves | 150-cap rate | Mean anomalies | RWX mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Delta Force installation | 339 | 69.29 | 66 | 149.22 | 150 | 98.23% | 3.12 | 0 |
| Windows System32 (x64) | 50 | 85.58 | 87 | 150 | 150 | 100% | 7.56 | 0 |
| Windows SysWOW64 (x86) | 50 | 71.16 | 70 | 147.42 | 150 | 98% | 2.42 | 0 |
| Windows control combined | 100 | 78.37 | 80 | 148.71 | 150 | 99% | 4.99 | 0 |

## Interpretation

- The Delta Force corpus is one software installation and is not a labelled malware benchmark.
- The Windows control corpus contains 50 Microsoft-signed x64 System32 binaries and 50 Microsoft-signed x86 SysWOW64 binaries.
- The detector is byte/alignment agnostic: it does not disassemble instructions, validate instruction boundaries, or prove control-flow reachability.
- A cave is a candidate byte range, not a verified code injection site.

## Reproduction

```powershell
.\scripts\Select-ControlCorpus.ps1
.\scripts\Build-Release.ps1 -Version 1.0.0
.\scripts\Build-CorpusComparison.ps1
```
