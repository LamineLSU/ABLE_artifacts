rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 00 10 00 00 0F 82 }
        $pattern1 = { 8D B0 74 0C 00 00 }
        $pattern2 = { 35 96 33 0C A4 E4 B7 }

    condition:
        any of them
}