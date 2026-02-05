rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 55 ?? 55 ?? ?? 8B 4D 0C 5D }
        $pattern1 = { 56 ?? 55 ?? 55 ?? ?? 8D B0 98 0C 00 00 5D }
        $pattern2 = { 56 55 55 55 ?? ?? 8B EC ?? ?? ?? ?? 8B 45 08 }

    condition:
        any of them
}