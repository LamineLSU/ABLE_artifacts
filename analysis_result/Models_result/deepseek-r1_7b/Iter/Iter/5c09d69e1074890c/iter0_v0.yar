rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B 36 5E ?? ?? ?? ?? ??:?? ?? }
        $pattern1 = { 8B 45 F8 EB ?? ??:?? ??:?? }
        $pattern2 = { 8B 55 0C ?? ??:??:?? ??:?? }
}

count = 3