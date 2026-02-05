rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns for sandbox analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC E8 50 8B 4C F2 7D 51 8D 95 F9 FE FF FF C1 ?? ?? ?? ?? 00 00 00 00 EB 00 00 00 00 00 00 00 40 EA 00 00 00 00 00 40 10 88 }
        $pattern1 = { FF 15 88 7C 42 00 00 00 00 00 EA 00 00 00 00 00 40 84 D8 }
        $pattern2 = { FF 15 88 7C 42 00 00 00 00 00 EA 00 00 00 00 00 40 82 D8 }

    condition:
        any of them
}