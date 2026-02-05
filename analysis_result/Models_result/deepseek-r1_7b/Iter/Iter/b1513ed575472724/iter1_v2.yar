rule Bypass_Sample {
    meta:
        description = "Evasion bypass using initial setup and conditional jump"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,cape_count=0"
        confidence = 65
    strings:
        $pattern0 = { 00 41 B9 01 ED ED 00 41 B9 03 EB 00 41 B9 05 E0 00 41 B9 06 CA 00 41 DF 02 }
        $pattern1 = { E8 F7 25 ?? ?? 83 F8 01 74 }
        $pattern2 = { E8 F7 25 ?? ?? FF 75 08 }
    condition:
        any of them
}