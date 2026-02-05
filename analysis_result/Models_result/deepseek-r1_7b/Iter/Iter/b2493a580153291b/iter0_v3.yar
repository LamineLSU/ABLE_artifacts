rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
    $pattern1 = { E8 ?? ?? ?? ?? FF ?C 50 F4 00 }
    $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}