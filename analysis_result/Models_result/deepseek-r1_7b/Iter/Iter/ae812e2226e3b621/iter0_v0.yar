rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF ?? BE C4 FF 15 AC B0 41 00 } 
        $pattern1 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF E0 00 00 ?? 3C 01 29 00 }
        $pattern2 = { 8B FF 55 8B EC FF 75 08 74 20 64 A1 30 00 00 00 FF 40 68 C1 E8 08 A8 01 FF 75 08 E8 15 AC B0 41 00 }

    condition:
        any of them
}