rule Bypass_Sample {
    meta:
        description = "Evasion bypass strategy targeting exit decisions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 }
        $pattern1 = { E8 B1 28 ?? ?? ?? }
        $pattern2 = { E8 1C 3C 03 ?? ?? }

    condition:
        any of them
}