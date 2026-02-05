rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 6E FF FF E8 2D 01 00 00 CC }
        $pattern1 = { 6A 00 E8 2D 01 00 00 CC }
        $pattern2 = { E8 2D 01 00 00 CC 8B 45 ?? }

    condition:
        any of them
}