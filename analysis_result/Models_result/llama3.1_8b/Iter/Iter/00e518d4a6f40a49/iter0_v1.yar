rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=??,action1=skip"

    strings:
        $pattern0 = { E8 C8 FF FF FF FF 75 08 59 }
        ?? = { [6-20 bytes] } // Pattern for conditional jump
        ?? = { [6-20 bytes with wildcards] } // Test/compare instruction pattern

    condition:
        any of them
}