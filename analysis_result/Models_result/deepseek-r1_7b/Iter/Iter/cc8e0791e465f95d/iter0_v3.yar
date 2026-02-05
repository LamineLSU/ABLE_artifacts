rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? ?? FF 75 C0 08 }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 FF 00 00 00 }
        $pattern2 = { ?? ?? ?? ?? FF 15 AC B0 41 00 }

    condition:
        any of them
}