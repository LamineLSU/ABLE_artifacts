rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { C7 85 94 FE FF FF 3C 00 00 00 }
        $pattern1 = { 6A 08 56 FF 15 44 04 40 }
        $pattern2 = { 81 FF 99 02 00 00 5F 5E 7D 08 }

    condition:
        any of them
}