rule EvasionBypass
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 08 3D 3F 03 8D 4C 24 1C E8 D2 CD FF FF }
        $pattern1 = { 68 48 3E 3F 03 8D 4D 50 53 E8 19 01 00 00 }
        $pattern2 = { 6A 01 5A 8B CE E8 12 08 00 00 85 C0 }

    condition:
        any of them
}