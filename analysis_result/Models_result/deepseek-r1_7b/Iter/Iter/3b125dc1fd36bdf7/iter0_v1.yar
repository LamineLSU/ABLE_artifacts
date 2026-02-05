rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 8B EC FF 15 BC A0 41 00 83 65 E4 00 E8 47 00 00 00 BA 3C 00 42 00 B9 00 00 42 00 }
        $pattern1 = { 0A 14 EC 47 55 FF 15 BC A0 41 00 83 F8 01 74 20 C1 E8 08 A8 01 FF 75 08 50 FF 15 14 A1 15 0A }
        $pattern2 = { 6A 5A E8 BB 21 00 00 74 20 C1 E8 08 A8 01 FF 75 08 50 FF 15 18 A1 15 0A FF 75 08 }

    condition:
        any of them
}