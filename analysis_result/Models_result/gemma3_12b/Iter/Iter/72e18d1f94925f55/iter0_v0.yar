rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 CD 3D 00 00 83 F8 01 74 20 }
        $pattern1 = { E8 BF 31 E7 04 90 50 E8 BE 31 E7 04 }
        $pattern2 = { E8 94 DB CB 74 90 CC }

    condition:
        any of them
}