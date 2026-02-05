rule Bypass_Sample {
    meta: description = "Evasion bypass rule"
    strings: $pattern0 = { 8B 45 6A ... }, etc.
}