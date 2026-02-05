rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection for a specific sequence in the trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 EA EA 74 12 00 EF 61 90 5A 00 00 00 5B 8B CE EC E8 F0 F1 CA DD 00 EF A1 2C }
        $pattern1 = { 6A ?? EB 53 ED 5D 33 CD EC EB 8B C8 EC E9 B4 00 EF 62 07 }
        $pattern2 = { FF F1 CA DD 00 EF A1 2C 33 FF ED ED 8B 45 ED 00 00 01 04 E8 C7 FB 00 EF 62 07 }
    condition:
        any of them
}