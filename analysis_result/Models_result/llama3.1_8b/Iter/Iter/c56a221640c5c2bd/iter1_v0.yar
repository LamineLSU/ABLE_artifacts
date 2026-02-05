rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 83 E4 F0 51 52 53 }
        $pattern1 = { 3D 00 10 00 00 0F 82 }
        $pattern2 = { 0F 31 C4 8B 44 24 10 }

    condition:
        any of them
}