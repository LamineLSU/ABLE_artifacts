rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 84 45 FC 68 C0 9E 05 E8 B9 ?? ?? ?? ?? FF 15 7C 64 ?? ?? FF 75 FC }
        $pattern1 = { 83 A5 AC FE FF FF 00 C8 85 CC FE FF FF 00 FF 15 2C 65 ?? ?? FF 15 2C 64 ?? ?? }
        $pattern2 = { 1B C0 83 D8 FF BB EA FF FF FF 84 45 DC DD EB 24 EA 8B 45 DC EA DD EB 24 83 DD 80 CD EB 28 00 00 00 00 }

    condition:
        any of them
}