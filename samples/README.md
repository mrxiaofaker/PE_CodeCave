# Sample Corpus

This directory contains metadata for the 339 PE reports used to evaluate PE CodeCave.

- `manifest.csv`: one row per original report, including SHA256, file size, source path, report name and report metrics.
- `summary.csv`: aggregate counts and score statistics.

The repository does **not** contain executable sample bodies. The manifest was generated from one locally installed Delta Force directory, so it is a real-world regression corpus rather than a labelled malware benchmark.

Verify every available file hash:

```powershell
.\scripts\Run-Dataset.ps1 -VerifyOnly
```

Rebuild the manifest from the original HTML reports:

```powershell
.\scripts\Build-SampleManifest.ps1
```

See the main [README](../README.md) for source details, aggregate statistics, reproduction instructions and false-positive limitations.
