rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 95 DB 0D 74 ?? ?? ?? ?? E8 CD 3D 00 00 }
        $pattern1 = { E8 94 DB 8D 74 ?? ?? ?? ?? E8 82 34 A3 04 }
        $pattern2 = { E8 34 6F 66 74 ?? ?? ?? ?? E8 3C 33 00 00 }

    condition:
        any of them
}