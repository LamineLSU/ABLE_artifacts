rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 50 A0 41 01 CA DD 01 41 A0 50 85 FF ED ED 74 39 01 3C A2 D6 8B 45 C4 EA DD EB 3C }
        $pattern1 = { 6A 00 00 00 00 00 FF 15 44 A0 41 01 CA DD 01 41 A0 44 50 EA FF 15 40 A0 41 01 CA DD 01 41 A0 40 }
        $pattern2 = { E8 08 8D 02 00 CA 01 3F 21 E6 FF 75 BC DD EB 44 E8 08 8D 02 00 CA 01 3F 21 E6 }

    condition:
        any of them
}