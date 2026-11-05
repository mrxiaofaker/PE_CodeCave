# Article and Release Version Alignment

## Status

The article preview is under review and cannot currently be edited. It references commit `0727f0d`. This repository keeps that commit available as the immutable tag `article-0727f0d`.

The current release tag is `v1.0.0`.

## Mapping

| Purpose | Reference |
| --- | --- |
| Article original baseline | `article-0727f0d` |
| Current release and comparison corpus | `v1.0.0` |
| Current `main` branch | Latest documentation and scripts |

The core detector remains the byte-run and PE-structure heuristic described by the article. The release adds native CLI automation, static runtime packaging, UTF-8 sources, safety fixes, a Microsoft-signed Windows control corpus and reproducible comparison reports. It does not introduce instruction decoding or control-flow validation.

## Article Baseline Numbers

The original 339-file corpus in `samples/manifest.csv` still reproduces the article's headline observations:

- 339 of 339 files contain at least one detected code cave.
- 333 of 339 files reach the per-file limit of 150 caves.
- All 339 paths are unique; there are 336 unique SHA256 values because three pairs contain duplicate binaries.

## New Comparison

The `v1.0.0` comparison adds 100 Microsoft-signed Windows system binaries:

- 50 from `C:\Windows\System32` (x64).
- 50 from `C:\Windows\SysWOW64` (x86).

See `samples/comparison.md`, `samples/control-manifest.csv` and `samples/v1.0.0-comparison.csv`.

The controls do not confirm the heuristic. They falsify the assumption that a high cave count is a useful maliciousness signal by itself. This is intentional evidence for the article's boundary analysis.

## Reproduction

```powershell
git checkout article-0727f0d

git checkout v1.0.0
.\scripts\Select-ControlCorpus.ps1
.\scripts\Build-Release.ps1 -Version 1.0.0
.\scripts\Build-CorpusComparison.ps1
```

The comparison outputs are generated with the `v1.0.0` binary and verified against the SHA256 values in the manifests.
