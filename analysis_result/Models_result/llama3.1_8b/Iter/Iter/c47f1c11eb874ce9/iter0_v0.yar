rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 FF D2 }
        $pattern1 = { 55 8B EC 8B 45 08 }
        $pattern2 = { 6A 35 56 51 8D B0 98 0C 00 00 }

    condition:
        any of them
}