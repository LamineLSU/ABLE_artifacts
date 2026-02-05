rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 55 8B EC 53 56 57 68 00 40 40 00 E8 90 F6 FF FF }
        $pattern2 = { 74 07 50 FF 15 50 B0 AB 00 FF 47 24 10 }
        $pattern3 = { 83 FF FF 74 1A 83 7C 24 18 }

    condition:
        any of them
}