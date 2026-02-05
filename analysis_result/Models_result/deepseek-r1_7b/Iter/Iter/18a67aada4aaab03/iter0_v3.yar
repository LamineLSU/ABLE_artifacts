rule Bypass_Escape {
    meta:
        description = "Evasion bypass for ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? }
        $pattern1 = { 64 A1 30 00 00 00 ?? ?? ?? ?? ?? ?? ?? }
        $pattern2 = { 8B 40 68 00 ?? ?? ?? ?? E8 F7 ?? }

    condition:
        any of them
}