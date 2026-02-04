---
name: yara-skill
description: Expert YARA rule authoring, review, and optimization. Use when writing new YARA rules, reviewing existing rules for quality issues, optimizing rule performance, or converting detection logic to YARA syntax. Covers rule naming conventions, string selection, condition optimization, performance tuning, and automated quality checks based on yaraQA.
---

# YARA Rule Authoring & Review

Expert guidance for writing high-quality, performant YARA rules based on industry best practices and automated QA checks.

> **Scope:** This skill covers readability, maintainability, and usability. For performance optimization (atoms, short-circuit evaluation), see the Performance Reference.

---

## Quick Start Template

```yara
rule MAL_Family_Platform_Type_Date {
    meta:
        description = "Detects ..."
        author = "Your Name"
        date = "2026-02-03"
        reference = "https://..."
        score = 75
    strings:
        $x1 = "unique malware string"
        $s1 = "grouped string 1"
        $s2 = "grouped string 2"
        $a1 = "Go build"
        $fp1 = "Copyright Microsoft"
    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and $a1
        and (
            1 of ($x*)
            or all of ($s*)
        )
        and not 1 of ($fp*)
}
```

---

## Rule Naming Convention

Format: `CATEGORY_SUBCATEGORY_DESCRIPTOR_DATE`

The rule name is often the first information shown to users. It should include:
- Type of threat
- Classification tags  
- Descriptive identifier
- Context/period of creation

Values are ordered from **generic to specific**, separated by underscores (`_`).

### Main Categories (Required)

| Prefix | Meaning | Example |
|--------|---------|---------|
|`MAL`|Malware|`MAL_APT_CozyBear_ELF_Apr18`|
|`HKTL`|Hack tool|`HKTL_PS1_CobaltStrike_Oct23`|
|`WEBSHELL`|Web shell|`WEBSHELL_APT_ASP_China_2023`|
|`EXPL`|Exploit code|`EXPL_CVE_2023_1234_WinDrv`|
|`VULN`|Vulnerable component|`VULN_Driver_Apr18`|
|`SUSP`|Suspicious/generic|`SUSP_Anomaly_LNK_Huge_May23`|
|`PUA`|Potentially unwanted app|`PUA_Adware_Win_Trojan`|

### Secondary Classifiers (Combine as needed)

**Intention/Background:**
- `APT` — Nation state actor
- `CRIME` — Criminal activity  
- `ANOMALY` — Generic suspicious characteristics
- `RANSOM` — Ransomware

**Malware Types:**
- `RAT`, `Implant`, `Stealer`, `Loader`, `Crypter`, `PEEXE`, `DRV`

**Platform:**
- `WIN` (default, often omitted), `LNX`, `MacOS`
- `X64` (default), `X86`, `ARM`, `SPARC`

**Technology:**
- `PE`/`ELF`, `PS`/`PS1`/`VBS`/`BAT`/`JS`
- `.NET`/`GO`/`Rust`, `PHP`/`JSP`/`ASP`
- `MalDoc`, `LNK`, `ZIP`/`RAR`

**Modifiers:**
- `OBFUSC` — Obfuscated
- `Encoded` — Encoded payload
- `Unpacked` — Unpacked payload
- `InMemory` — Memory-only detection

**Packers/Installers:**
- `SFX`, `UPX`, `Themida`, `NSIS`

**Uniqueness Suffixes:**
- MonthYear: `May23`, `Jan19`, `Apr18`
- Number: `*_1`, `*_2`

### Naming Examples

```
APT_MAL_CozyBear_ELF_Loader_Apr18
    └── APT malware loader by CozyBear for Linux (April 2018)

SUSP_Anomaly_LNK_Huge_Apr22
    └── Suspicious anomaly: oversized link file (April 2022)

MAL_CRIME_RANSOM_PS1_OBFUSC_Loader_May23
    └── Crime ransomware: obfuscated PowerShell loader (May 2023)
```

---

## Rule Structure & Formatting

### Indentation

Use **3-4 spaces** consistently. Never mix tabs and spaces.

**DON'T:**
```yara
rule BAD_EXAMPLE {
meta:
description = "no indentation"
strings:
$s1 = "value"
}
```

**DO:**
```yara
rule GOOD_EXAMPLE {
   meta:
      description = "proper 3-space indent"
      author = "Name"
   strings:
      $s1 = "value"
   condition:
      uint16(0) == 0x5a4d
      and filesize < 300KB
}
```

### Rule Tags

Put **main categories in the rule name**. Additional tags go in a `tags` meta field:

```yara
rule MAL_APT_CozyBear_Win_Trojan_Apr18 {
    meta:
        tags = "APT28, Gazer, phishing"
    ...
}
```

---

## Meta Data Fields

### Mandatory Fields

| Field | Format | Guidelines |
|-------|--------|------------|
|`description`|String|60-400 chars, start with "Detects ...", no URLs|
|`author`|String|Full name or Twitter handle; comma-separated for multiple|
|`reference`|String|URL or "Internal Research"; avoid unstable/private links|
|`date`|YYYY-MM-DD|Creation date only (use `modified` for updates)|

### Optional Fields

| Field | Format | Purpose |
|-------|--------|---------|
|`score`|0-100|Severity × specificity for prioritization|
|`hash`|String(s)|SHA256 preferred; can use multiple times|
|`modified`|YYYY-MM-DD|Last update date|
|`old_rule_name`|String|Previous name for searchability|
|`tags`|Comma-separated|Extra classification tags|
|`license`|String|License identifier|

### Score Guidelines

| Score | Significance | Examples |
|-------|--------------|----------|
|0-39|Very Low|Capabilities, common packers|
|40-59|Noteworthy|Uncommon packers, PE anomalies|
|60-79|Suspicious|Heuristics, obfuscation, generic rules|
|80-100|High|Direct malware/hack tool matches|

---

## String Categories ($x, $s, $a, $fp)

Organize strings using the **Triad Approach** plus false positive filters:

| Prefix | Meaning | Usage |
|--------|---------|-------|
|`$x*`|Highly specific|Unique to threat; `1 of ($x*)` triggers|
|`$s*`|Grouped strings|Need multiple; `all of ($s*)` or `3 of ($s*)`|
|`$a*`|Pre-selection|Narrows file type; use early in condition|
|`$fp*`|False positive filters|Exclude benign; `not 1 of ($fp*)`|

### Example

```yara
rule HKTL_Go_EasyHack_Oct23 {
   meta:
      description = "Detects a Go based hack tool"
      author = "John Galt"
      date = "2023-10-23"
      reference = "https://example.com/EasyHack"
   strings:
      $a1 = "Go build"              // Pre-selection: Go binary

      $x1 = "Usage: easyhack.exe -t [IP] -p [PORT]"
      $x2 = "c0d3d by @EdgyHackerFreak"

      $s1 = "main.inject"
      $s2 = "main.loadPayload"

      $fp1 = "Copyright by CrappySoft" wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20MB
      and $a1
      and (
        1 of ($x*)
        or all of ($s*)
      )
      and not 1 of ($fp*)
}
```

### String Identifier Best Practices

**Opt for readable values:**
```yara
// AVOID:
$s1 = { 46 72 6F 6D 42 61 73 65 36 34 }

// USE:
$s1 = "FromBase64"
```

**Choose concise identifiers:**
```yara
// AVOID:
$string_value_footer_1 = "eval("
$selection_14 = "eval("

// USE:
$s1 = "eval("
$eval = "eval("
```

### Hex String Formatting

Add ASCII comments for readability. Wrap at 16-byte intervals.

```yara
/* )));
IEX( */
$s1 = { 29 29 29 3b 0a 49 45 58 28 0a }

// Long hex wrapped at 16 bytes:
$s1 = { 2c 20 2a 79 6f 77 2e 69 20 26 20 30 78 46 46 29 
        3b 0a 20 20 70 72 69 6e 74 66 20 28 28 28 2a 79 }
```

---

## Condition Formatting

### Structure Template

```yara
condition:
    header_check
    and file_size_limitation
    and other_limitations
    and string_combinations
    and false_positive_filters
```

### Formatting Rules

- **New line before `and`**
- **Indent blocks for `or` groups**
- **Group related conditions with parentheses**

**Example:**
```yara
condition:
    uint16(0) == 0x5a4d
    and filesize < 300KB
    and pe.number_of_signatures == 0
    and (
        1 of ($x*)
        or (
            2 of ($s*)
            and 3 of them
        )
    )
    and not 1 of ($fp*)
```

**Multi-value conditions:**
```yara
condition:
    (
        uint16(0) == 0x5a4d     // MZ marker
        or uint16(0) == 0x457f  // ELF marker
    )
    and filesize < 300KB
    and all of ($s*)
```

---

## Performance Critical Rules

### String Length
- Minimum effective atom: **4 bytes**
- Avoid: `"MZ"`, `{ 4D 5A }`, repeating chars (`AAAAAA`)
- Use `uint16(0) == 0x5A4D` for short header checks

### Regex
- Always include **4+ byte anchor**
- Avoid: `.*`, `.+`, unbounded quantifiers `{x,}`
- Prefer: `.{1,30}` with upper bound

### Condition Order
```yara
// GOOD: Cheap first, expensive last
uint16(0) == 0x5A4D
and filesize < 100KB
and all of them
and math.entropy(500, filesize-500) > 7

// BAD: Expensive first
math.entropy(...) > 7 and uint16(0) == 0x5A4D
```

### Module Alternatives
```yara
// AVOID: Parses entire file
import "pe"
condition: pe.is_pe

// USE: Header check only
condition: uint16(0) == 0x5A4D
```

See [references/performance.md](references/performance.md) for detailed optimization.

---

## Common Issues (yaraQA)

### Logic Errors

| ID | Issue | Problem | Fix |
|----|-------|---------|-----|
|`CE1`|Never matches|`2 of them` with only 1 string|Adjust count|
|`SM2`|PDB + fullword|PDBs start with `\`, `fullword` breaks match|Remove `fullword`|
|`SM3`|Path + fullword|`\Section\` won't match with `fullword`|Remove `fullword`|
|`SM5`|Problematic chars|`fullword` with `.` `)` `_` etc.|Remove `fullword`|
|`CS1`|Substring string|One string is substring of another|Remove redundant string|
|`DS1`|Duplicate strings|Same value defined twice|Consolidate|

### Performance Warnings

| ID | Issue | Problem | Fix |
|----|-------|---------|-----|
|`PA1`|Short at position|`$mz at 0`|Use `uint16(0) == 0x5A4D`|
|`PA2`|Short atom|< 4 bytes|Extend with context bytes|
|`RE1`|Unanchored regex|No 4+ byte fixed prefix|Add anchor|
|`CF1`|Expensive calc|Hash/math over full file|Move to end of condition|
|`NC1`|`nocase` letters only|Generates many atoms|Add special char or use regex|

See [references/yaraqa-checks.md](references/yaraqa-checks.md) for complete reference.

---

## Modifiers Reference

| Modifier | Atom Count | Best Practice |
|----------|------------|---------------|
|`ascii`|1|Default if no modifier specified|
|`wide`|1|UTF-16, use when needed|
|`ascii wide`|2|Both encodings|
|`nocase`|Up to 16|Avoid on short strings; use regex `[Pp]attern` instead|
|`fullword`|Word boundary|Avoid with paths starting `\` or ending `\`|
|`xor`|256 variations|Use sparingly; consider single byte xor instead|

---

## Tweaks

### String Matching vs. Hashing

Avoid hashing loops — use direct string matching:

```yara
// LESS EFFICIENT:
for any var_sect in pe.sections:
   (hash.md5(var_sect.raw_data_offset, 0x100) == "d99eb1e503...")

// MORE EFFICIENT:
strings:
   $section_hash = { d9 9e b1 e5 03 ca c3 a1 ... }
condition:
   $section_hash
```

---

## Review Workflow

When reviewing YARA rules:

1. **Structure** — Naming convention, metadata completeness, indentation
2. **Strings** — Triad categorization ($x/$s/$a/$fp), length, readability
3. **Conditions** — Short-circuit order, logic errors, impossible matches
4. **Performance** — Module usage, regex anchors, short atoms
5. **Style** — Hex formatting, identifier naming

Reference yaraQA issue IDs when suggesting improvements.

---

## Rule Validation (Required)

**Every YARA rule must be validated before returning it to the user.**

Before presenting any new or modified rule, run it through the validation script to ensure it compiles correctly:

```bash
# From file
python scripts/validate_rule.py rule.yar

# From stdin (for in-memory rules)
echo 'rule test { condition: true }' | python scripts/validate_rule.py --stdin
```

### Validation Workflow

1. **Write/modify the rule** following the guidelines above
2. **Run validation** — pipe the rule directly or save to temp file
3. **If validation fails** — fix the syntax errors and re-validate
4. **If validation passes** — return the rule to the user

### Validation Output

The script uses YARA-X to compile the rule and reports:
- **Compilation errors** — Syntax issues that prevent the rule from working
- **Warnings** — Potential issues that should be reviewed

```
==================================================
YARA RULE VALIDATION
==================================================

Rule: MAL_Example_Jan24

✓ Compilation: PASSED

==================================================
```

### Never Skip Validation

- **Do not** return a rule without validating it first
- **Do not** assume a rule is correct based on visual inspection
- **Always** fix any compilation errors before presenting the rule

This ensures users receive syntactically correct, working YARA rules.

---

## Resources

### References
- [references/style.md](references/style.md) — Complete naming, structure, formatting
- [references/performance.md](references/performance.md) — Atoms, optimization, conditions
- [references/yaraqa-checks.md](references/yaraqa-checks.md) — All 20 automated checks
- [references/issue-identifiers.md](references/issue-identifiers.md) — Complete issue ID reference (50+ IDs)

### Scripts
- [scripts/validate_rule.py](scripts/validate_rule.py) — YARA-X syntax validation
