# Security Advisory

## Typecho GetText Plural-Forms eval() Remote Code Execution

**GHSA ID**: Pending  
**CVE ID**: CAN-2026-2030628 (pending)  
**Published**: 2026-05-28  
**Severity**: HIGH (CVSS 7.2)  
**CWE**: CWE-95 (Eval Injection), CWE-94 (Code Injection)

### Summary

A code injection vulnerability exists in Typecho v1.3.0 and earlier. The GetText internationalization module uses PHP eval() to dynamically execute Plural-Forms expressions extracted from MO translation files without any sanitization.

### Affected Versions

| Product | Version Range |
|---------|--------------|
| Typecho Blog Platform | 0 through 1.3.0 |

### Impact

An attacker who can modify translation files can inject arbitrary PHP code into the Plural-Forms header. This code executes when any page request triggers plural translation logic via the _n() function, leading to complete compromise of confidentiality, integrity, and availability.

### Vulnerability Details

The selectString() function in var/Typecho/I18n/GetText.php uses eval() to execute a string derived from the Plural-Forms header of MO translation files, with no input sanitization.

### Proof of Concept

Modify the Plural-Forms header in any MO translation file:

Original (benign): Plural-Forms: nplurals=1; plural=0;
Malicious: Plural-Forms: nplurals=1; plural=0;system('id');

Visit any page that triggers plural translation with count != 1.

### Remediation

Replace eval() with a safe expression parser or apply strict whitelist regex validation.

### Credits

Discovered by: Cowork 3P
Discovery Date: May 28, 2026

### References

Typecho GitHub: https://github.com/typecho/typecho
Vulnerable Code: https://github.com/typecho/typecho/blob/master/var/Typecho/I18n/GetText.php
