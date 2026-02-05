rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific early functions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 49 E8 25 05 00 00 }
        $pattern1 = { 6C 7E 3D 41 E8 53 }
        $pattern2 = { 49 E8 B3 03 00 00 }

    condition:
        any of them
}