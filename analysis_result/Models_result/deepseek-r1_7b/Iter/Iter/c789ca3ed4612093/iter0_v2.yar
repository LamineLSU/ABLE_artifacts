rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 ?? ?? ?? ?? }
        $pattern1 = { C1 E8 75 10 ?? ?? ?? ?? }
        $pattern2 = { A8 01 8B 40 ?? ?? ?? ?? }

    condition:
        any_of them
}