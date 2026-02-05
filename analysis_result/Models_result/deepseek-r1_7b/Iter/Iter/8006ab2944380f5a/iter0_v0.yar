rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting suspicious point detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 24 13 00 0A 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ??. ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? }

    condition:
        any of them
}