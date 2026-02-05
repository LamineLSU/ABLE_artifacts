rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 ?? FF D2 CA ED }
        $pattern1 = { 56 6A 36 00 00 00 36 6A 00 00 00 00 00 }
        $pattern2 = { 52 ED E8 24 13 00 00 CA 00 41 F2 33 8B 55 0C ED DD EB 0C }

    condition:
        any of them
}