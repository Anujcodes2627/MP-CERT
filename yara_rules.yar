
/* Rule 1: Simple ASCII string match
   Why: Demonstrates the most basic YARA usage (literal string).
   How: Matches a literal ASCII string.
   Use: Good for detecting specific markers, keywords, or known signatures.
*/
rule basic_string_marker_1 {
    strings:
        $s1 = "EVIL_MARKER_1234"
    condition:
        $s1
}

/* Rule 2: Case-insensitive string match
   Why: Showcases case-insensitive matching for indicators that may vary.
   How: nocase modifier makes it case-insensitive.
   Use: Useful for matching tags or file contents where casing isn't guaranteed.
*/
rule case_insensitive_marker {
    strings:
        $s1 = "suspicious_function" nocase
    condition:
        $s1
}

/* Rule 3: Wide (UTF-16) string match
   Why: Many Windows binaries embed UTF-16 strings.
   How: wide modifier matches UTF-16-LE encoded versions.
   Use: Detects UTF-16 text inside binaries or documents.
*/
rule wide_utf16_string {
    strings:
        $s1 = "HelloFromMalware" wide
    condition:
        $s1
}

/* Rule 4: Hex pattern (byte sequence)
   Why: Demonstrates matching a specific byte sequence.
   How: Hex string matches exact bytes; useful for small known shellcode or sequence.
   Use: Good for matching distinctive byte patterns in binaries.
*/
rule hex_pattern_example {
    strings:
        $p1 = { 6A 00 68 00 30 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
    condition:
        $p1
}

/* Rule 5: Regular expression match
   Why: Show regex matching for flexible patterns (e.g., C2-like URLs).
   How: /regex/ syntax; can include modifiers.
   Use: Detects patterns like domains, IPs, or obfuscated strings.
*/
rule regex_c2_like {
    strings:
        $r1 = /https?:\/\/[a-z0-9\.\-]{3,}\.(com|net|info)(\/[^\s"]*)?/i
    condition:
        $r1
}

/* Rule 6: Multiple strings required
   Why: Reduce false positives by requiring multiple indicators.
   How: Use boolean logic (and) between string matches.
   Use: Typical in production rules to require several matches before alerting.
*/
rule multiple_indicators {
    strings:
        $a = "password=" nocase
        $b = "Authorization:" nocase
    condition:
        $a and $b
}

/* Rule 7: String count threshold
   Why: Trigger only if many occurrences appear (e.g., large suspicious payload).
   How: # operator counts matches.
   Use: Filter noise — only match when count >= threshold.
*/
rule repeated_token_threshold {
    strings:
        $t = "XOR_KEY"
    condition:
        #t >= 3
}

/* Rule 8: Filename / metadata usage placeholder
   Why: Shows combining filename metadata with content (some YARA runners add metadata).
   How: Uses filename variable if the runner sets it; otherwise content-only.
   Use: Search for filenames that look malicious in file collections.
*/
rule suspicious_filename_and_content {
    meta:
        description = "If runner provides filename, combine with content match"
    strings:
        $s = "evil_payload"
    condition:
        $s and (filename =~ /.*(invoice|resume|payment).*/i)
}

/* Rule 9: PE imports (requires pe module when running with YARA that has modules)
   Why: Detect suspicious API imports in PE files (e.g., CreateRemoteThread).
   How: Uses the 'pe' module to check imported functions.
   Use: Useful for spotting binaries that import process-injection or networking APIs.
*/
import "pe"
rule pe_suspicious_imports {
    meta:
        description = "Detects suspicious Windows API imports"
    condition:
        pe.imports("kernel32.dll", "CreateRemoteThread") or
        pe.imports("ws2_32.dll", "connect")
}

/* Rule 10: PE section size anomaly (intermediate)
   Why: Detects suspicious PE section with large entropy or odd sizes.
   How: Uses pe.sections and simple heuristic (section size > threshold).
   Use: Flag packed or unusual binaries.
*/
rule pe_large_section {
    meta:
        description = "Flags PE with at least one very large section"
    condition:
        for any i in pe.sections : ( i.size > 0x200000 ) /* >2MB */
}

/* Rule 11: Entropy-based heuristic (approximate)
   Why: High-entropy sections often indicate packing/encryption.
   How: Uses pe.section_entropy if available; fallback to false if module not available.
   Use: Triage packed samples.
*/
rule pe_high_entropy_section {
    meta:
        description = "Matches if any PE section has high entropy (>7.5)"
    condition:
        any of pe.sections and any section : ( section.entropy > 7.5 )
}

/* Rule 12: YARA modules logic: strings + PE import check
   Why: Combine content-based and structural checks to reduce false positives.
   How: require both a suspicious string and suspicious import.
   Use: More reliable detection for real-world binaries.
*/
rule combined_pe_string_imports {
    strings:
        $s = "cmd.exe" nocase
    condition:
        $s and pe.imports("kernel32.dll", "CreateProcessA")
}

/* Rule 13: XOR-encoded small pattern detection (simple)
   Why: Detect common simple XOR obfuscation with a 1-byte key.
   How: Use a short 'for' loop in condition to test XOR with keys 1..255.
   Use: Useful to detect very simple single-byte XOR obfuscation of known marker.
   Note: This is illustrative; real XOR-decoding conditions usually use 'for' with indexed access and
         yara's 'uint8' helpers are limited; adapt as needed when running in your environment.
*/
rule xor_1byte_simple_marker {
    strings:
        $m = "TEST_SECRET"
    condition:
        for any i in (1..255) : ( for any s in ($m) : true ) /* placeholder: adapt for real decoding */
}

/* Rule 14: Filename extension check (content runner dependent)
   Why: Some environments expose 'filename' meta — detect executable masquerading as doc.
   How: Use filename regex; note: depends on runner.
   Use: Detect 'invoice.doc.exe' style tricks.
*/
rule double_extension_masquerade {
    condition:
        filename =~ /.*\.(doc|pdf)\.exe$/i
}

/* Rule 15: Heuristic: many suspicious keywords
   Why: Score-based matching where many different suspicious strings increase confidence.
   How: count of multiple labeled strings.
   Use: Useful in sandbox outputs, scripts, or text logs.
*/
rule heuristic_many_keywords {
    strings:
        $k1 = "kill_process" nocase
        $k2 = "bypass" nocase
        $k3 = "obfuscate" nocase
        $k4 = "shellcode" nocase
        $k5 = "open_port" nocase
    condition:
        (#k1 + #k2 + #k3 + #k4 + #k5) >= 2
}

/* Rule 16: Null-byte separated wide-like markers (mixed encodings)
   Why: Catch strings where characters are separated by null bytes (UTF-16LE without proper wide modifier).
   How: Regex that allows nulls between characters.
   Use: Handy for detecting sloppy Unicode encodings.
*/
rule null_separated_marker {
    strings:
        $r = /e\x00v\x00i\x00l\x00/i
    condition:
        $r
}

/* Rule 17: File size heuristic
   Why: Some malware families use very small single-file scripts or very large dumps.
   How: Use filesize variable if runner supports it.
   Use: Filter obvious benign files by size.
*/
rule tiny_script_file {
    condition:
        filesize < 1024 and (uint16(0) == 0 /* placeholder check; adapt to your runner */)
}

/* Rule 18: Combination: regex + count + time heuristic comment
   Why: Show combining regex with counts to detect many suspicious URL occurrences.
   How: Regex finds URLs; require at least 2 matches.
   Use: Detect documents embedding multiple suspicious links.
*/
rule multiple_suspicious_urls {
    strings:
        $url = /http:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?(\/\S*)?/
    condition:
        #url >= 2
}

/* Rule 19: Short PE stub detection (possible dropper)
   Why: Extremely small PE files (few KB) can be droppers or stagers.
   How: Check pe.size or filesize if runner supports it.
   Use: Triage tiny executables.
*/
rule small_pe_stub {
    condition:
        pe and pe.size < 4096
}

/* Rule 20: Generic heuristic safe-fail rule (useful as baselining)
   Why: Demonstrates a rule that explicitly requires both textual and binary signs to reduce false positives.
   How: Requires multiple different kinds of matches.
   Use: Baseline rule you can tweak for your environment.
*/
rule combined_heuristic_str_and_hex {
    strings:
        $a = "malicious_toolkit" nocase
        $b = { 90 90 90 90 68 ?? ?? ?? ?? }
    condition:
        $a and $b
}
