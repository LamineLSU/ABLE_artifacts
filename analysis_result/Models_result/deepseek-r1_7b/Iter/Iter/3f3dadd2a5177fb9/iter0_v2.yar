rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 F7 25 00 00 FF 75 08 FF 15 3C 13 30 00 }
        $pattern2 = { FF 75 08 FF 15 40 C1 33 00 FF 15 50 C1 33 00 }
    condition:
        any of them
}