rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 83 EC 10 74 08 }
        $pattern1 = { 3D 00 10 00 00 74 0A }
        $pattern2 = { E8 74 0A 00 00 8B 55 14 }

    condition:
        any of them
}