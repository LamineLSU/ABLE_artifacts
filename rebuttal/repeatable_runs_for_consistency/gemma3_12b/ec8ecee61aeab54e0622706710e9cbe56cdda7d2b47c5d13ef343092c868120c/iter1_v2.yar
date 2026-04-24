rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 08 3D 3F 03 8D 4C 24 1C E8 D2 CD FF FF }
        $pattern1 = { 8D 4C 24 48 E8 19 01 00 00 50 68 AC 30 3F 03 }
        $pattern2 = { 8D 4C 24 28 E8 AB 00 00 00 8D 8C 24 88 00 00 00 }

    condition:
        any of them
}