rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? ?? ?? ?? FF 75 08 DD EB 08 }
        $pattern1 = { E8 F7 25 00 00 CA 00 41 DE D2 74 20 00 41 B9 00 FF 75 08 DD EB 08 }
        $pattern2 = { E8 0B 00 00 00 CA 00 41 B9 13 FF 75 08 DD EB 08 }

    condition:
        any of them
}