rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection based on function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 56 8B 55 0C E8 04 13 00 8B 55 14 }
        $pattern1 = { 56 F8 14 00 00 74 ?? }
        $pattern2 = { ?? ?? ?? 0F 84 9C E8 04 13 00 }
    condition:
        any of them
}