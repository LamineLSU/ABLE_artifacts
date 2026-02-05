rule EvasionBypass {
    meta:
        description = "Evasion bypass detection for memory and subroutine calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF FF 75 08 E8 C8 FF FF FF FF 15 AC B0 41 00 }  // 6 bytes
        $pattern1 = { 8B EC FF 75 08 E8 C8 FF FF FF FF 15 AC B0 41 00 }  // 6 bytes
        $pattern2 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF FF 15 AC B0 41 00 }  // 13 bytes with wildcards
    condition:
        any_of_them
}