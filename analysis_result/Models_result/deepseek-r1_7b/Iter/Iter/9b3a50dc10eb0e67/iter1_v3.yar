rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass rule - evolved with three patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 59 }
        $pattern1 = { 74 ?? 0F 85 C0 ?? ?? ?? ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? FF 15 5C 01 B8 00 CA DD 00 B8 01 5C }
        $pattern2 = { 8B 45 FC 59 FF 75 08 DD EB 08 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 }

    condition:
        any of them
}