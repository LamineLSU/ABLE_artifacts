rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific operation sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C8 8A 01 3C 22 75 28 }
        $pattern1 = { E8 2D 00 00 00 56 E8 1D 00 00 00 56 }
        $pattern2 = { 3C 22 74 11 7F 07 75 F5 }

    condition:
        (any of the patterns match)
}