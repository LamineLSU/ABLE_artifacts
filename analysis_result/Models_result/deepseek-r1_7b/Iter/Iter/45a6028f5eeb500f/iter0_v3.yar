rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 ?? ?? }
        $pattern1 = { 8B FF 55 8B EC 00 40 E7 C3 ?? ?? }
        $pattern2 = { 8B FF 55 8B EC EC A8 ?? ?? ?? }
    condition:
        any of them
}