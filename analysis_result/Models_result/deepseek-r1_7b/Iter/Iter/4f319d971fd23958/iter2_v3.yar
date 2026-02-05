rule Bypass_Sample_Evolved
{
    meta:
        description = "Bypass evasion detection by targeting early decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A ?? ?? ?? ?? ?? }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern2 = { ?? ?? 99 00 00 00 0F 82 }

    condition:
        any of them
}