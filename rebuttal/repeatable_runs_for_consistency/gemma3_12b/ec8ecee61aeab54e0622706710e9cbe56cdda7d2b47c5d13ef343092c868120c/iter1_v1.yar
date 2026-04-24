rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 4C 24 1C E8 AB 00 00 00 8D 4C 24 60 E8 AB 00 00 00 68 08 3D 46 00 }
        $pattern1 = { 8D 4C 24 1C E8 AB 00 00 00 8D 4C 24 60 E8 AB 00 00 00 68 08 3D 46 00 8D 4C 24 1C }
        $pattern2 = { 8D 4C 24 1C E8 AB 00 00 00 8D 4C 24 60 E8 AB 00 00 00 68 08 3D 46 00 8D 4C 24 1C E8 D2 CD FF FF }

    condition:
        any of them
}