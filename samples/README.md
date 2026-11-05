# Sample Corpus

This directory contains metadata for the 339 PE reports used to evaluate PE CodeCave.

- `manifest.csv`: one row per original report, including SHA256, file size, source path, report name and report metrics.
- `summary.csv`: aggregate counts and score statistics.
- `control-manifest.csv`: 50 Microsoft-signed System32 x64 binaries and 50 SysWOW64 x86 binaries.
- `v1.0.0-comparison.csv`: 439 files analyzed with the v1.0.0 release binary.
- `v1.0.0-summary.csv`: category-level comparison metrics.
- `comparison.md`: concise comparison table and interpretation.

The repository does **not** contain executable sample bodies. The manifest was generated from one locally installed Delta Force directory, so it is a real-world regression corpus rather than a labelled malware benchmark.

The Windows control corpus is not malware either. Its purpose is to test whether the current byte-run heuristic discriminates between software sources. The result is intentionally reported even though it weakens the detector's claimed specificity.

Verify every available file hash:

```powershell
.\scripts\Run-Dataset.ps1 -VerifyOnly
```

Rebuild the manifest from the original HTML reports:

```powershell
.\scripts\Build-SampleManifest.ps1
```

See the main [README](../README.md) for source details, aggregate statistics, reproduction instructions and false-positive limitations.
