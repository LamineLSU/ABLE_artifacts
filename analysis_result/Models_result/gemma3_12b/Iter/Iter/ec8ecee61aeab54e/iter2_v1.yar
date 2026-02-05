rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 4C 24 30 E8 AB 00 00 00 8D 4C 24 60 }
        $pattern1 = { 68 08 3D 46 00 8D 4C 24 1C E8 D2 CD FF FF }
        $pattern2 = { 8B D6 8B E8 E1 FE FF FF 59 59 84 C0 }

    condition:
        any of them
}