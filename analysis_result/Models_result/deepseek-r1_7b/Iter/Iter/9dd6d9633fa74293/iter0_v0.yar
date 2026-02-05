rule Bypass_Evasion {
    meta:
        description = "Evasion bypass targeting call instructions with offset displacement"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF C8 55 00 00 00 ?? ?? }
        $pattern1 = { FC F3 4B CE E8 00 FF C8 55 00 00 ?? }
        $pattern2 = { 8B EC FF 75 08 ?? }
    condition:
        any of them
}