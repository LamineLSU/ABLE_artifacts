rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 D4 B0 75 D4 B0 75 D4 B0 }
        $pattern1 = { E8 ?? ?? ?? ?? ?? C4 ?? ?? C4 ?? }
        $pattern2 = { FF 35 D8 B0 35 D8 B0 35 D8 B0 }

    condition:
        any of them
}