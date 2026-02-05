rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detected through TEST/CMP and function calls."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF FF 75 08 8B EC FF 75 08 E8 C8 FF FF FF 59 FF 75 08 E8 C8 FF FF FF }
        $pattern1 = { 8B FF 55 8B EC 0F 84 33 FD FF FF E8 25 05 00 00 5A 6A 5B E8 74 FA FF FF E8 B8 5F 0F EF FF E9 B5 FC FF FF }
        $pattern2 = { 8B FF FF 75 08 8B EC FF 75 08 E8 C8 FF FF FF 59 FF 75 08 E8 C8 FF FF FF CC }

    condition:
        any of them
}