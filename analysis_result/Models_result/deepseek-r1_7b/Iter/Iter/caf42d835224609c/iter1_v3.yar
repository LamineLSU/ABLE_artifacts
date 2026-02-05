rule Bypass_Sample_Evasion {
    meta:
        description = "Evasion bypass detection for specific decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 74 ?? 0C ?? 75 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}