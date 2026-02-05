rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 94 DB 19 75 90 50 E8 F4 2D 68 04 90 FF 75 08 E8 0B 00 00 00 }
        $pattern1 = { E8 12 35 81 04 90 50 E8 11 35 81 04 90 FF 75 08 E8 0B 00 00 00 }
        $pattern2 = { E8 95 DB 13 75 90 59 FF 75 08 E8 0B 00 00 00 }

    condition:
        any of them
}