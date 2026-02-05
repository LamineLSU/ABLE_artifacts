rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 38 DD FF 15 38 41 41 00 6A 00 FF 75 F8 6A 00 FF 75 FC 6A 00 FF 35 D4 B0 41 00 FF 15 D0 44 41 00 EB 38 DD }
        $pattern1 = { 00 41 38 F5 A3 C8 B0 41 00 ?? ?? ?? ?? 6A 02 FF 15 28 44 41 00 6A 00 FF 15 70 44 41 00 74 10 }
        $pattern2 = { 00 41 38 F5 A3 C8 B0 41 00 ?? ?? ?? ?? FF 15 48 44 41 00 FF 15 8C 44 41 00 6A 00 FF 15 5E C4 41 00 6A 00 }

    condition:
        any of them
}