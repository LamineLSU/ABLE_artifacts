rule Evasion_Bypass_Patterns {
    meta:
        description = "Evasion bypass patterns to prevent exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 33 DB 03 C3 05 00 BA 04 00 03 0C 97 A5 1F 5D 0A 00 }

    condition:
        any of them
}