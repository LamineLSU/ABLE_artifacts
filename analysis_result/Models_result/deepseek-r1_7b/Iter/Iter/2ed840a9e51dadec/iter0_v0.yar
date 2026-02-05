rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection rules targeting memory/procedure calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 CC 5B 5E 03 C3 8B 4D E8 25 01 00 00 }
        $pattern1 = { 6A 5B 5A 8B CE E8 03 C9 8B 45 CC FF 0E 74 8C 00 00 00 }
        $pattern2 = { FF 15 AC B0 41 00 8B 40 68 1A 30 30 28 C1 E8 08 75 08 }

    condition:
        (any($pattern0, $pattern1, $pattern2))
}