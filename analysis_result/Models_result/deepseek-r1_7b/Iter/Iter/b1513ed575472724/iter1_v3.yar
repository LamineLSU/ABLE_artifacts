rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting the sample code"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {E8 F7 25 ?? ???}
        $pattern1 = {A8 01 ????}
        $pattern2 = {64 A1 30 ???}

    condition:
        any of them
}