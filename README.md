# StaticElf

Static analysis toolkit for ELF binaries. Designed for malware research, cross-architecture comparison, and ML-based family classification.

Produced by Wolfpack Cybernetics.

---

## Overview

StaticElf is a three-file Python toolkit for extracting structural, behavioural, and assembly-level features from ELF binaries. It operates entirely statically — no execution, no emulation, no kernel interaction.

The toolkit is designed around two use cases:

1. **Interactive analysis** — inspect a binary or compare two binaries from the terminal, with optional HTML report output.
2. **Dataset construction** — scan a directory of binaries and emit one flat JSON per file, ready for ingestion into a pandas DataFrame or numpy array for machine learning.

---

## Files

| File | Role |
|---|---|
| `elfanalyzer.py` | Core library. `ELFAnalyzer` class. No CLI logic. Importable directly. |
| `staticelf.py` | CLI tool. All argument parsing, terminal output, and HTML generation. |
| `asmanalyzer.py` | Assembly analysis engine. `ASMAnalyzer` class. Requires capstone. |

---

## Requirements

```
python >= 3.10
pyelftools >= 0.29
capstone >= 4.0        # optional — required for --asm and assembly signals in --xdiff
numpy                  # optional — required for --output npz
```

Install dependencies:

```bash
pip install pyelftools capstone numpy
```

---

## Quick Start

```bash
# Full analysis of a single binary
python staticelf.py /path/to/binary

# Export to JSON
python staticelf.py /path/to/binary --output json --out-file result.json

# Diff two binaries (same architecture)
python staticelf.py --diff binary_v1 binary_v2 --out-file diff.html

# Cross-architecture similarity (two binaries)
python staticelf.py --xdiff tsh.x86 tsh.arm

# Cross-architecture similarity matrix (N binaries)
python staticelf.py --xdiff tsh.x86 tsh.arm tsh.mips tsh.aarch64 --out-file matrix.html

# Assembly analysis
python staticelf.py --asm /path/to/binary --asm-cfg-html asm_report.html

# Bulk scan for ML dataset
python staticelf.py --scan-dir ./samples/ --output-dir ./dataset/
```

---

## Analysis Modes

### Single Binary Analysis

```bash
python staticelf.py BINARY [options]
```

Runs full analysis and prints results to the terminal. Use display filters to show only specific sections:

```bash
python staticelf.py BINARY --hashes --security --arch
python staticelf.py BINARY --imports --entropy
python staticelf.py BINARY --strings --strings-limit 100
```

Output formats:

```bash
python staticelf.py BINARY --output json --out-file result.json
python staticelf.py BINARY --output csv  --out-file features.csv
python staticelf.py BINARY --output npz  --out-file features.npz
```

Multiple binaries can be passed in a single invocation. With `--output csv`, each binary appends a row to the same file.

---

### Binary Diff (`--diff`)

Compares two ELF binaries of the same architecture at the byte and structure level. Useful for version diffing or patch analysis.

```bash
python staticelf.py --diff binary_a binary_b
python staticelf.py --diff binary_a binary_b --out-file report.html
python staticelf.py --diff binary_a binary_b --output json --out-file diff.json
```

Diff output covers: hashes, file size delta, section changes (added, removed, modified), import changes, per-section entropy delta, and string changes.

---

### Cross-Architecture Diff (`--xdiff`)

Compares binaries compiled from the same or similar source across different CPU architectures. Hash and byte-level comparison is meaningless across architectures; `--xdiff` uses structural and semantic signals instead.

**Two binaries — pairwise comparison:**

```bash
python staticelf.py --xdiff tsh.x86 tsh.arm
python staticelf.py --xdiff tsh.x86 tsh.arm --out-file xdiff.html
python staticelf.py --xdiff tsh.x86 tsh.arm --output json --out-file xdiff.json
```

**Three or more binaries — N x N similarity matrix:**

```bash
python staticelf.py --xdiff tsh.x86 tsh.arm tsh.mips tsh.ppc tsh.aarch64
python staticelf.py --xdiff tsh.* --out-file matrix.html
```

The matrix HTML report includes a colour-coded heatmap, a binary index table with architecture details, and a ranked pairs table with per-signal scores.

#### Similarity Signals and Weights

| Signal | Weight | Method |
|---|---|---|
| Strings | 25% | Cosine similarity of printable string sets |
| Assembly | 18% | Cosine similarity of semantic instruction histograms |
| Imports | 20% | Cosine similarity of imported function name sets |
| Symbols | 15% | Cosine similarity of named symbol sets |
| Entropy | 10% | Cosine similarity of per-section entropy vectors |
| Function count | 7% | Ratio of STT_FUNC symbol counts |
| Section layout | 5% | Section name Jaccard + count ratio |

The final score is a weighted sum in the range 0.0 to 1.0. Confidence thresholds:

| Score | Confidence |
|---|---|
| >= 0.75 | HIGH |
| >= 0.45 | MEDIUM |
| < 0.45 | LOW |

---

### Assembly Analysis (`--asm`)

Disassembles the top-N functions by size and reports instruction-level metrics. Requires capstone.

```bash
python staticelf.py --asm BINARY
python staticelf.py --asm BINARY --asm-top-n 200
python staticelf.py --asm BINARY --asm-cfg-html report.html
```

All metrics are derived from linear disassembly only. No control flow edge inference is performed, and no dead code detection is attempted — indirect branch targets cannot be resolved reliably under static analysis, and reporting speculative results was deliberately avoided.

Reported metrics per function:

- Instruction count
- Basic block count (terminator-based, conservative)
- Average instructions per block

Reported metrics per binary:

- Total instruction count across analysed functions
- Average instructions per function
- Average blocks per function
- Top-10 mnemonic frequency table
- Semantic instruction distribution (memory, arithmetic, branch, logic, call, ret, other)

The semantic distribution groups architecture-specific mnemonics into common categories, making it meaningful for cross-architecture comparison. This is the signal used by `--xdiff` for the assembly similarity score.

Supported architectures: x86, x86_64, ARM (32-bit), AArch64, MIPS (32/64), PowerPC (32/64).

---

### Bulk Scan (`--scan-dir`)

Scans a flat directory of ELF binaries and writes one ML-ready JSON per file. Non-ELF files are silently skipped. Files that fail analysis are logged without halting the scan.

```bash
python staticelf.py --scan-dir ./samples/ --output-dir ./dataset/
```

Output files written to `--output-dir`:

| File | Contents |
|---|---|
| `<md5>.json` | Flat feature dict for the binary (one per binary) |
| `manifest.json` | Index mapping MD5 to SHA256 and original path |
| `summary.json` | Counts, architecture breakdown, IOC verdict distribution, timing |
| `errors.log` | Failed files with reason (if any) |

The `summary.json` file includes a `high_suspicion` list of binaries rated HIGH or CRITICAL by the IOC engine, allowing rapid triage without loading the full dataset.

---

## IOC Detection

The IOC engine runs automatically as part of `analyze()` and `--scan-dir`. It analyses extracted strings and performs a raw binary pass for encoded content.

Detection categories:

| Category | Method |
|---|---|
| IPv4 addresses | Regex with octet range validation; loopback and broadcast filtered |
| IPv6 addresses | Regex, full and compressed forms |
| URLs | http, https, ftp, ftps, sftp schemes |
| Domains | Regex against a curated TLD list |
| Sensitive file paths | Prefix and exact match against known sensitive paths |
| Shell commands | Keyword match against a curated malware-relevant command set |
| Syscall strings | Keyword match against suspicious libc and syscall names |
| Base64 blobs | Regex for decodable blobs >= 32 characters |
| XOR-encoded strings | Sliding-window single-byte XOR scan across the first 8 MB |
| Crypto indicators | PEM private key headers, Bitcoin addresses |

Each binary receives a severity score (0.0 to 1.0) and a verdict:

| Score | Verdict |
|---|---|
| >= 0.80 | CRITICAL |
| >= 0.60 | HIGH |
| >= 0.35 | MEDIUM |
| >= 0.10 | LOW |
| < 0.10 | CLEAN |

---

## ML Feature Schema

Each `<md5>.json` produced by `--scan-dir` is a single flat dict — one row in a pandas DataFrame. Fields are grouped as follows.

**Identity** (drop before fitting):

`original_path`, `md5`, `sha256`

**Architecture:**

`arch_machine` (str, encode as categorical), `arch_abi`, `arch_elf_type`, `arch_entry_point`, `arch_bits` (int), `arch_endianness` (0=little, 1=big)

**File:**

`file_size`, `is_dynamic`

**Imports:**

`import_count`, `import_func_count`, `import_obj_count`, `import_weak_count`, `import_names` (list, drop for numpy)

**Symbols:**

`symbol_count`, `symbol_func_count`, `symbol_obj_count`

**Sections:**

`section_count`, `section_mean_size`, `section_total_size`, `section_exec_count`, `section_write_count`

**Strings:**

`string_count`, `string_mean_len`, `string_max_len`

**Security** (all 0/1 except `sec_relro` which is 0/1/2):

`sec_nx`, `sec_pie`, `sec_canary`, `sec_relro`, `sec_stripped`, `sec_debug`, `sec_fortify`

**Entropy:**

`entropy_whole_binary`, `entropy_text`, `entropy_data`, `entropy_rodata`, `entropy_bss`, `entropy_plt`, `entropy_got`

**IOC counts:**

`ioc_ipv4_count`, `ioc_ipv6_count`, `ioc_url_count`, `ioc_domain_count`, `ioc_path_count`, `ioc_shell_cmd_count`, `ioc_syscall_count`, `ioc_b64_count`, `ioc_xor_count`, `ioc_crypto_count`, `ioc_severity_score`, `ioc_verdict_ordinal` (CLEAN=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4)

**Assembly** (zero if capstone not installed):

`asm_available`, `asm_function_count`, `asm_total_instructions`, `asm_avg_instr_per_func`, `asm_avg_blocks_per_func`, `asm_avg_instr_per_block`, `asm_wl_histogram` (JSON string)

### Loading into pandas

```python
import json
import glob
import pandas as pd

records = []
for path in glob.glob("./dataset/*.json"):
    with open(path) as f:
        records.append(json.load(f))

df = pd.DataFrame(records)

# Encode categorical architecture fields
for col in ("arch_machine", "arch_abi", "arch_elf_type"):
    df[col] = pd.Categorical(df[col]).codes

# Expand WL histogram into individual columns
wl = df["asm_wl_histogram"].apply(json.loads).apply(pd.Series).fillna(0)
wl.columns = [f"wl_{c}" for c in wl.columns]
df = pd.concat([df, wl], axis=1)

# Drop identity and non-numeric fields before fitting
drop_cols = ["original_path", "md5", "sha256", "import_names", "asm_wl_histogram"]
X = df.drop(columns=drop_cols)
```

---

## Library Usage

`elfanalyzer.py` can be imported directly without the CLI:

```python
from elfanalyzer import ELFAnalyzer

az = ELFAnalyzer("/path/to/binary")
result = az.analyze()

print(az.arch)
print(az.security)
print(az.iocs["verdict"])
print(az.iocs["severity"])

# Assembly analysis (requires capstone)
az.analyze_asm(top_n=100)
print(az.asm["semantic_histogram"])

# Export flat ML JSON
az.to_ml_json("/path/to/output.json")

# Append row to CSV
az.to_pandas_csv("/path/to/features.csv")
```

Cross-architecture similarity between two analyzed binaries:

```python
from elfanalyzer import ELFAnalyzer

a = ELFAnalyzer("tsh.x86")
a.analyze()
a.analyze_asm()

b = ELFAnalyzer("tsh.arm")
b.analyze()
b.analyze_asm()

score = a._asm_analyzer.wl_similarity(b._asm_analyzer)
print(f"Assembly similarity: {score:.4f}")
```

---

## Supported ELF Architectures

x86, x86_64, ARM (32-bit), AArch64, MIPS, MIPS64, PowerPC, PowerPC64, IBM S/390, SPARC, SPARCv9, IA-64, RISC-V, LoongArch, Motorola 68k, SuperH, Xtensa, AVR, MSP430.

Assembly disassembly (capstone) is supported on: x86, x86_64, ARM, AArch64, MIPS (32/64), PowerPC (32/64).

---

## Notes on Static Analysis Limitations

Cross-architecture comparison is inherently approximate. Legitimate differences between binaries compiled from the same source include:

- Compiler backend optimisations differ per target (inlining, loop unrolling, instruction selection)
- `sizeof` and ABI differences cause real branch divergence at the source level
- Platform-specific `#ifdef` guards produce genuinely different code paths per target

The similarity score should be interpreted as a structural and semantic fingerprint, not a definitive proof of common origin. Scores above 0.75 across multiple signals provide strong evidence of a shared codebase.

---

## License

Copyright Wolfpack Cybernetics. All rights reserved.
