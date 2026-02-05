rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection using specific memory address and stack manipulation patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF 84 33 CD E8 ?? 00 5A ?? 8B CE E8 ?? }
        $pattern1 = { 6A 5B ?? ?? 8B EC 0F 84 33 CA E8 ?? FF ?? 8B 41 04 ?? }
        $pattern2 = { 74 0D ?? 8B 45 04 ?? FF 00 0C 6A ?? FF 8F 00 ?? E8 39 57 ?? }

    condition:
        any of them
}