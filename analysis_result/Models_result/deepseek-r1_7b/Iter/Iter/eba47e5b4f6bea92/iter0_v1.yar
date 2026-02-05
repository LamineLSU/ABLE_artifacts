rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection using multiple patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 EB EB ?? ?? ?? ?? E8 25 05 00 }
        $pattern1 = { 74 12 B9 42 00 00 01 3C EA ED E8 C8 FF FF FF ?? ?? ?? ?? FF 15 AC B0 41 00 }
        $pattern2 = { 6A 5B 00 00 00 5B EC E8 74 FA FF FF EA ED F8 E5 F0 FE FF FF FF 15 88 A1 30 00 }

    condition:
        any of them
}