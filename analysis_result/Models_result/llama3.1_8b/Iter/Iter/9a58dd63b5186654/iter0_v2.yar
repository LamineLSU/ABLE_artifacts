rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 83 F8 11 74 05 ?? FF 15 4C 60 44 00 }
        $pattern1 = { 6A 00 56 ?? E8 0D DA 01 00 FF 15 4C 60 44 00 }
        $pattern2 = { 50 8B EC 83 E4 F8 ?? FF 15 84 94 45 00 }

    condition:
        any of them
}