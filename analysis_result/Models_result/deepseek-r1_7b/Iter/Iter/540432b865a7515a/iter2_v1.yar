rule Bypass_Sample {
    meta:
        description = "Evasion bypass using different call paths"
        cape_options = "bp0=E8 05 ?? 0F 84 59, bp1=E9 0A ?? 74 ?1E 5A, bp2=FF 15 ?? 0F 84 5B"

    strings:
        $pattern0 = { E8 05 ?? 0F 84 59 }
        $pattern1 = { E9 0A ?? 74 ?1E 5A }
        $pattern2 = { FF 15 ?? 0F 84 5B }
}