rule Evasion_Bypass_Patterns {
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B 45 BE 36 55 E6 F6 00 01 F0 A0 00 03 B9 F7 5D 00 00 00 }
        $pattern1 = { E8 8C 0F E3 00 38 02 D8 00 5C 0A 00 00 3B 9F 75 D0 00 00 }
        $pattern2 = { 6A 40 8B 74 00 00 00 04 00 00 00 15 00 00 00 00 }

    condition:
        any of them
}