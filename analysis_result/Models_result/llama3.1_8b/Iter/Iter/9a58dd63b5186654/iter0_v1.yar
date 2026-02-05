rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 ?? 11 ?? ?? ?? 58 }
        $pattern1 = { 33 ?? 8B ?? ?? 44 ?? }
        $pattern2 = { A1 ?? ?? 33 ?? 8B ?? ?? }

    condition:
        any of them
}