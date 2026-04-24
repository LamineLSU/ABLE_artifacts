rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 08 3D 3F 03 8D 4C 24 1C E8 D2 CD FF FF }
        $pattern1 = { 8D 4C 24 60 E8 AB 00 00 00 8D 4C 24 1C E8 D2 CD FF FF }
        $pattern2 = { 68 08 3D 3F 03 8D 4C 24 14 E8 D2 CD FF FF }

    condition:
        any of them
}