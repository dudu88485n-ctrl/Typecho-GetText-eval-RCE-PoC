# Typecho eval() GetText Technical Analysis

## The Vulnerability

The eval() call in var/Typecho/I18n/GetText.php:371 is CWE-95 (Eval Injection).

### selectString() - Lines 361-376

```php
private function selectString(int $n): int
{
    $string = $this->getPluralForms();
    $string = str_replace('nplurals', "\$total", $string);
    $string = str_replace("n", $n, $string);
    $string = str_replace('plural', "\$plural", $string);
    $total = 0;
    $plural = 0;
    eval("$string");  // VULNERABLE
    if ($plural >= $total) { $plural = $total - 1; }
    return $plural;
}
```

### getPluralForms() - Lines 384-406

```php
private function getPluralForms(): string
{
    if (!is_null($header) && preg_match("/plural\-forms: ([^\n]*)\n/i", $header, $regs)) {
        $expr = $regs[1];  // NO FILTERING
    }
    return $this->pluralHeader;
}
```

### Why eval() is not called when $number == 1

In ngettext() at line 145-160, selectString() is only called when $number != 1.

## Attack Vectors

1. Administrator with Theme Editor access (VUL-001)
2. File upload vulnerability to replace MO files
3. Database compromise to modify translation cache
4. Supply chain attack via malicious theme/plugin MO files
