rule EvasionBypass {
    meta:
        description = "Evasion bypass patterns targeting memory tests"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF ?? ?? ?? ?? FF 40 68 C1 E8 EA 08 75 10 00 B5 A9 D0 FF 75 08 DD EB 08 FF 15 AC B0 41 00 CA DD 00 41 B0 AC }
        $pattern1 = { 85 C0 55 8B EC E8 07 26 00 00 ?? ?? AE CA FF 15 8C E1 B6 00 }
        $pattern2 = { 6A 5A 55 8B EC 8B EC E8 07 26 00 00 EA 01 00 B5 A9 D0 FF 75 08 DD EB 08 FF 15 40 E1 B6 00 CA DD 00 B6 E1 40 }

    condition:
        any of them
}