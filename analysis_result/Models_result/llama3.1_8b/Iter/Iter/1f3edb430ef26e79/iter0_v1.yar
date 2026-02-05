rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 38 ?? ?? 83 C4 14 ?? 52 }
        $pattern1 = { 8B 06 ?? ?? 83 C4 14 ?? 52 }
        $pattern2 = { 83 C4 14 ?? 52 ?? 8B 55 2C }

    condition:
        any of them
}