rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 83 C4 F0 8B D8 54 E8 B0 C8 F9 FF }
        $pattern1 = { 66 81 3C 24 E4 07 73 07 6A 00 E8 D1 C7 F9 FF }
        $pattern2 = { 81 FB 01 00 80 0F 94 C0 8B D8 6A 00 E8 6B 25 FE FF }

    condition:
        any of them
}