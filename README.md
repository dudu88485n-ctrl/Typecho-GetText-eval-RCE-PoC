# Typecho GetText Plural-Forms eval() Remote Code Execution

## Overview

A code injection vulnerability (CWE-95) exists in Typecho v1.3.0 and earlier. The GetText internationalization module uses PHP's `eval()` to dynamically execute Plural-Forms expressions extracted from MO translation files without any sanitization.

**CVSS 3.1**: 7.2 HIGH — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`

## Affected Code

- **File**: `var/Typecho/I18n/GetText.php`
- **Function**: `selectString()` (line 371) — `eval("$string")`
- **Function**: `getPluralForms()` (line 396) — regex extraction without filtering

## Quick Start

### Verification (PHP)
```bash
php verify_eval_injection.php
```

### Build malicious MO file
```bash
python3 build_malicious_mo.py
```

## Vulnerability Chain

```
_n() → I18n::ngettext() → GetTextMulti::ngettext()
  → GetText::ngettext() → selectString()
    → getPluralForms() [extracts Plural-Forms header from MO file]
    → str_replace() [variable substitution]
    → eval("$string") [ATTACKER CODE EXECUTED]
```

## Remediation

Replace `eval()` with a safe expression parser or apply strict whitelist validation on the Plural-Forms expression.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-28 | Vulnerability discovered |
| 2026-05-28 | PoC verified |
| TBD | CVE assigned |
| TBD | Vendor notified |

## License

This repository is for security research purposes only.
