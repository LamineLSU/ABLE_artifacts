rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 56 68 D0 07 00 00 }
        $pattern1 = { 83 F8 11 74 05 8B C0 }
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}