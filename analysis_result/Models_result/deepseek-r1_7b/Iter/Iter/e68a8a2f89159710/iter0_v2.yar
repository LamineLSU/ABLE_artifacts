rule Bypass_Evasion_Patterns {
    meta:
        description = "Evasion bypass detection rules based on trace analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 64 A1 30 00 00 00 00 00 74 01 5A 8B CC ?? }

    condition:
        any of them
}